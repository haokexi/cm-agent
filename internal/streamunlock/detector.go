package streamunlock

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	metricStatusName = "cm_agent_stream_unlock_status"
	metricLastUpdate = "cm_agent_stream_unlock_last_update_timestamp_seconds"

	statusYes     = "yes"
	statusNo      = "no"
	statusFailed  = "failed"
	statusUnknown = "unknown"
	statusNoPrem  = "noprem"
	statusCN      = "cn"
	statusOrgOnly = "org"
	statusWebOnly = "web"
	statusAppOnly = "app"
	statusIDC     = "idc"

	typeNative  = "native"
	typeDNS     = "dns"
	typeUnknown = "unknown"
)

var (
	tiktokRegionRe      = regexp.MustCompile(`"region"\s*:\s*"([A-Za-z]{2,3})"`)
	netflixRegionRe1    = regexp.MustCompile(`"requestCountry"\s*:\s*\{\s*"id"\s*:\s*"([A-Za-z]{2})"`)
	netflixRegionRe2    = regexp.MustCompile(`"countryCode"\s*:\s*"([A-Za-z]{2})"`)
	youtubeRegionRe     = regexp.MustCompile(`"contentRegion"\s*:\s*"([A-Za-z]{2})"`)
	primeVideoRegionRe  = regexp.MustCompile(`"currentTerritory"\s*:\s*"([A-Za-z]{2})"`)
	redditRegionRe      = regexp.MustCompile(`country="([A-Za-z]{2})"`)
	openAITraceRegionRe = regexp.MustCompile(`(?m)^loc=([A-Za-z]{2})$`)
)

type Config struct {
	Logger    *slog.Logger
	Interval  time.Duration
	Timeout   time.Duration
	UserAgent string
}

type Result struct {
	Service    string
	Status     string
	Region     string
	UnlockType string
	CheckedAt  time.Time
}

type Detector struct {
	mu sync.RWMutex

	logger    *slog.Logger
	interval  time.Duration
	timeout   time.Duration
	userAgent string
	client    *http.Client

	statusDesc     *prometheus.Desc
	lastUpdateDesc *prometheus.Desc

	results    []Result
	lastUpdate time.Time
	nextRun    time.Time
	running    bool
}

func NewDetector(cfg Config) *Detector {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 30 * time.Minute
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	ua := strings.TrimSpace(cfg.UserAgent)
	if ua == "" {
		ua = "Mozilla/5.0 (compatible; cm-agent/streamunlock)"
	}

	d := &Detector{
		logger:    logger,
		interval:  interval,
		timeout:   timeout,
		userAgent: ua,
		client: &http.Client{
			Timeout: timeout + 2*time.Second,
		},
		statusDesc: prometheus.NewDesc(
			metricStatusName,
			"Stream unlock probe status by service. Value is always 1; sample timestamp indicates freshness.",
			[]string{"service", "status", "region", "unlock_type"},
			nil,
		),
		lastUpdateDesc: prometheus.NewDesc(
			metricLastUpdate,
			"Last successful stream unlock refresh unix timestamp in seconds.",
			nil,
			nil,
		),
	}

	now := time.Now()
	d.results = defaultResults(now)
	d.nextRun = now
	return d
}

func (d *Detector) Describe(ch chan<- *prometheus.Desc) {
	ch <- d.statusDesc
	ch <- d.lastUpdateDesc
}

func (d *Detector) Collect(ch chan<- prometheus.Metric) {
	d.maybeRefresh(time.Now())

	d.mu.RLock()
	results := make([]Result, len(d.results))
	copy(results, d.results)
	lastUpdate := d.lastUpdate
	d.mu.RUnlock()

	for _, r := range results {
		ch <- prometheus.MustNewConstMetric(
			d.statusDesc,
			prometheus.GaugeValue,
			1,
			r.Service,
			r.Status,
			r.Region,
			r.UnlockType,
		)
	}

	if !lastUpdate.IsZero() {
		ch <- prometheus.MustNewConstMetric(d.lastUpdateDesc, prometheus.GaugeValue, float64(lastUpdate.Unix()))
	}
}

func (d *Detector) maybeRefresh(now time.Time) {
	d.mu.Lock()
	if d.running || now.Before(d.nextRun) {
		d.mu.Unlock()
		return
	}
	d.running = true
	d.nextRun = now.Add(d.interval)
	d.mu.Unlock()

	go d.refresh(now)
}

func (d *Detector) refresh(now time.Time) {
	defer func() {
		d.mu.Lock()
		d.running = false
		d.mu.Unlock()
	}()

	results := d.runChecks(now)
	if len(results) == 0 {
		results = defaultResults(now)
	}

	d.mu.Lock()
	d.results = results
	d.lastUpdate = now
	d.mu.Unlock()
}

func (d *Detector) runChecks(now time.Time) []Result {
	services := []string{"tiktok", "netflix", "youtube_premium", "primevideo", "reddit", "chatgpt"}
	out := make([]Result, 0, len(services))
	ch := make(chan Result, len(services))
	var wg sync.WaitGroup

	for _, service := range services {
		service := service
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
			defer cancel()
			res := d.checkService(ctx, service, now)
			ch <- res
		}()
	}

	wg.Wait()
	close(ch)

	byService := make(map[string]Result, len(services))
	for res := range ch {
		byService[res.Service] = normalizeResult(res)
	}
	for _, service := range services {
		res, ok := byService[service]
		if !ok {
			res = Result{Service: service, Status: statusFailed, UnlockType: typeUnknown, CheckedAt: now}
		}
		out = append(out, normalizeResult(res))
	}
	return out
}

func defaultResults(now time.Time) []Result {
	services := []string{"tiktok", "netflix", "youtube_premium", "primevideo", "reddit", "chatgpt"}
	out := make([]Result, 0, len(services))
	for _, service := range services {
		out = append(out, Result{
			Service:    service,
			Status:     statusUnknown,
			UnlockType: typeUnknown,
			CheckedAt:  now,
		})
	}
	return out
}

func normalizeResult(r Result) Result {
	r.Service = normalizeToken(strings.ToLower(strings.TrimSpace(r.Service)), "unknown")
	r.Status = normalizeStatus(r.Status)
	r.Region = normalizeRegion(r.Region)
	r.UnlockType = normalizeUnlockType(r.UnlockType)
	if r.CheckedAt.IsZero() {
		r.CheckedAt = time.Now()
	}
	return r
}

func normalizeStatus(status string) string {
	s := normalizeToken(strings.ToLower(strings.TrimSpace(status)), statusUnknown)
	switch s {
	case statusYes, statusNo, statusFailed, statusUnknown, statusNoPrem, statusCN, statusOrgOnly, statusWebOnly, statusAppOnly, statusIDC:
		return s
	default:
		return statusUnknown
	}
}

func normalizeUnlockType(v string) string {
	s := normalizeToken(strings.ToLower(strings.TrimSpace(v)), typeUnknown)
	switch s {
	case typeNative, typeDNS, typeUnknown:
		return s
	default:
		return typeUnknown
	}
}

func normalizeRegion(v string) string {
	x := strings.TrimSpace(v)
	if x == "" {
		return ""
	}
	x = strings.ToUpper(x)
	if len(x) > 16 {
		x = x[:16]
	}
	return normalizeToken(x, "")
}

func normalizeToken(v string, fallback string) string {
	if v == "" {
		return fallback
	}
	b := strings.Builder{}
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	out := b.String()
	if out == "" {
		return fallback
	}
	if len(out) > 64 {
		return out[:64]
	}
	return out
}

func (d *Detector) checkService(ctx context.Context, service string, now time.Time) Result {
	switch service {
	case "tiktok":
		return d.checkTikTok(ctx, now)
	case "netflix":
		return d.checkNetflix(ctx, now)
	case "youtube_premium":
		return d.checkYouTubePremium(ctx, now)
	case "primevideo":
		return d.checkPrimeVideo(ctx, now)
	case "reddit":
		return d.checkReddit(ctx, now)
	case "chatgpt":
		return d.checkChatGPT(ctx, now)
	default:
		return Result{Service: service, Status: statusUnknown, UnlockType: typeUnknown, CheckedAt: now}
	}
}

func (d *Detector) checkTikTok(ctx context.Context, now time.Time) Result {
	res := Result{Service: "tiktok", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "tiktok.com"), CheckedAt: now}
	code, body, err := d.httpGet(ctx, "https://www.tiktok.com/", nil)
	if err != nil {
		return res
	}
	if code == http.StatusForbidden || code == http.StatusUnavailableForLegalReasons {
		res.Status = statusNo
		return res
	}
	cloudflareGate := strings.Contains(body, "Please wait")
	if cloudflareGate {
		_, body2, err2 := d.httpGet(ctx, "https://www.tiktok.com/explore", nil)
		if err2 == nil && body2 != "" {
			body = body2
		}
	}
	region := firstMatch(body, tiktokRegionRe)
	if region == "" {
		return res
	}
	res.Region = region
	if cloudflareGate {
		res.Status = statusIDC
	} else {
		res.Status = statusYes
	}
	return res
}

func (d *Detector) checkNetflix(ctx context.Context, now time.Time) Result {
	res := Result{Service: "netflix", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "netflix.com"), CheckedAt: now}

	codeOriginal, bodyOriginal, errOriginal := d.httpGet(ctx, "https://www.netflix.com/title/81280792", nil)
	codeNonOriginal, bodyNonOriginal, errNonOriginal := d.httpGet(ctx, "https://www.netflix.com/title/70143836", nil)
	if errOriginal != nil && errNonOriginal != nil {
		return res
	}

	region := firstMatch(bodyOriginal, netflixRegionRe1)
	if region == "" {
		region = firstMatch(bodyOriginal, netflixRegionRe2)
	}
	if region == "" {
		region = firstMatch(bodyNonOriginal, netflixRegionRe1)
	}
	if region == "" {
		region = firstMatch(bodyNonOriginal, netflixRegionRe2)
	}
	res.Region = region

	originalOK := netflixTitleAvailable(codeOriginal, bodyOriginal)
	nonOriginalOK := netflixTitleAvailable(codeNonOriginal, bodyNonOriginal)

	switch {
	case originalOK && nonOriginalOK:
		res.Status = statusYes
	case originalOK && !nonOriginalOK:
		res.Status = statusOrgOnly
	case !originalOK && !nonOriginalOK:
		res.Status = statusNo
	default:
		res.Status = statusNo
	}
	return res
}

func netflixTitleAvailable(code int, body string) bool {
	if code < 200 || code >= 400 {
		return false
	}
	l := strings.ToLower(body)
	blockedMarkers := []string{
		"not available in your region",
		"title is not available",
		"nsez-403",
		"unavailable for watching",
		"404 not found",
		"page-404",
	}
	for _, marker := range blockedMarkers {
		if strings.Contains(l, marker) {
			return false
		}
	}
	return true
}

func (d *Detector) checkYouTubePremium(ctx context.Context, now time.Time) Result {
	res := Result{Service: "youtube_premium", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "www.youtube.com"), CheckedAt: now}
	headers := map[string]string{"Accept-Language": "en"}
	code, body, err := d.httpGet(ctx, "https://www.youtube.com/premium", headers)
	if err != nil {
		return res
	}
	if code == http.StatusForbidden || code == http.StatusUnavailableForLegalReasons {
		res.Status = statusNo
		return res
	}

	l := strings.ToLower(body)
	if strings.Contains(l, "www.google.cn") {
		res.Status = statusCN
		res.Region = "CN"
		return res
	}
	if strings.Contains(l, "premium is not available in your country") {
		res.Status = statusNoPrem
		return res
	}

	region := firstMatch(body, youtubeRegionRe)
	res.Region = region
	if strings.Contains(l, "ad-free") || strings.Contains(l, "youtube premium") {
		res.Status = statusYes
		return res
	}
	res.Status = statusNo
	return res
}

func (d *Detector) checkPrimeVideo(ctx context.Context, now time.Time) Result {
	res := Result{Service: "primevideo", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "www.primevideo.com"), CheckedAt: now}
	code, body, err := d.httpGet(ctx, "https://www.primevideo.com", nil)
	if err != nil {
		return res
	}
	if code == http.StatusForbidden || code == http.StatusUnavailableForLegalReasons {
		res.Status = statusNo
		return res
	}
	region := firstMatch(body, primeVideoRegionRe)
	if region == "" {
		res.Status = statusNo
		return res
	}
	res.Status = statusYes
	res.Region = region
	return res
}

func (d *Detector) checkReddit(ctx context.Context, now time.Time) Result {
	res := Result{Service: "reddit", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "reddit.com"), CheckedAt: now}
	code, body, err := d.httpGet(ctx, "https://www.reddit.com/", nil)
	if err != nil {
		return res
	}
	switch code {
	case http.StatusOK:
		res.Status = statusYes
		res.Region = firstMatch(body, redditRegionRe)
		return res
	case http.StatusForbidden, http.StatusUnavailableForLegalReasons:
		res.Status = statusNo
		return res
	default:
		res.Status = statusFailed
		return res
	}
}

func (d *Detector) checkChatGPT(ctx context.Context, now time.Time) Result {
	res := Result{Service: "chatgpt", Status: statusFailed, UnlockType: d.detectUnlockType(ctx, "chat.openai.com"), CheckedAt: now}

	_, apiBody, apiErr := d.httpGet(ctx, "https://api.openai.com/compliance/cookie_requirements", nil)
	_, iosBody, iosErr := d.httpGet(ctx, "https://ios.chat.openai.com/", nil)
	_, traceBody, traceErr := d.httpGet(ctx, "https://chat.openai.com/cdn-cgi/trace", nil)
	if traceErr == nil {
		res.Region = firstMatch(traceBody, openAITraceRegionRe)
	}

	apiBlocked := strings.Contains(strings.ToLower(apiBody), "unsupported_country")
	iosBlocked := strings.Contains(strings.ToLower(iosBody), "vpn")

	switch {
	case apiErr != nil && iosErr != nil:
		res.Status = statusFailed
	case apiBlocked && iosBlocked:
		res.Status = statusNo
	case !apiBlocked && iosBlocked && apiErr == nil:
		res.Status = statusWebOnly
	case apiBlocked && !iosBlocked && iosErr == nil:
		res.Status = statusAppOnly
	case !apiBlocked && !iosBlocked && apiErr == nil && iosErr == nil:
		res.Status = statusYes
	case apiErr == nil && !apiBlocked:
		res.Status = statusYes
	default:
		res.Status = statusFailed
	}
	return res
}

func (d *Detector) httpGet(ctx context.Context, url string, headers map[string]string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("User-Agent", d.userAgent)
	req.Header.Set("Accept", "*/*")
	for k, v := range headers {
		if strings.TrimSpace(k) == "" || strings.TrimSpace(v) == "" {
			continue
		}
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return resp.StatusCode, "", err
	}
	return resp.StatusCode, string(body), nil
}

func firstMatch(body string, re *regexp.Regexp) string {
	if body == "" || re == nil {
		return ""
	}
	m := re.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(m[1]))
}

func (d *Detector) detectUnlockType(ctx context.Context, domain string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return typeUnknown
	}
	public, err1 := d.domainHasPublicIP(ctx, domain)
	wildcard, err2 := d.domainHasPublicIP(ctx, fmt.Sprintf("test-%d-%d.%s", time.Now().Unix(), rand.Int63(), domain))
	if err1 != nil && err2 != nil {
		return typeUnknown
	}
	if !public || wildcard {
		return typeDNS
	}
	return typeNative
}

func (d *Detector) domainHasPublicIP(ctx context.Context, domain string) (bool, error) {
	resolver := net.DefaultResolver
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		return false, err
	}
	for _, addr := range addrs {
		if isPublicIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalMulticast() || ip.IsLinkLocalUnicast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		if v4[0] == 10 {
			return false
		}
		if v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31 {
			return false
		}
		if v4[0] == 192 && v4[1] == 168 {
			return false
		}
		if v4[0] == 169 && v4[1] == 254 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
		return true
	}
	b := ip.To16()
	if b == nil {
		return false
	}
	if b[0] == 0xfc || b[0] == 0xfd {
		return false
	}
	if b[0] == 0xfe && (b[1]&0xc0) == 0x80 {
		return false
	}
	return true
}
