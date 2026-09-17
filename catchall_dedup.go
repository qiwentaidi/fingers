package fingers

import (
	"context"
	"crypto/md5"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/panjf2000/ants/v2"

	"github.com/qiwentaidi/clients"
	httputil "github.com/qiwentaidi/utils/http"
)

// catchAllProbeTimeout 候选上下文路径存活/catch-all 探测超时(秒)。
const catchAllProbeTimeout = 6

// defaultContextPathsPerOrigin contextPathsForTarget 返回的路径数上限。
// JS 路由派生的 context 路径会进入主动指纹的「context 路径 × 指纹专属路径」乘法,
// 不封顶时大路由 SPA + catch-all 网关可再次制造任务爆炸。
const defaultContextPathsPerOrigin = 20

// hashBody 对 body 做 md5,先按 maxInfoReponseSize 截断,保证根/候选用同一规范化。
func hashBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	limited := httputil.LimitResponseBytes(body, maxInfoReponseSize)
	sum := md5.Sum(limited)
	return fmt.Sprintf("%x", sum)
}

// rootBodyHash 返回该 origin 根路径响应 body 的 md5 hex。
// 根 body 在 FingerScan 阶段由 storeJSContextPage 存入 pageContextBodies(仅 deepScan 时存)。
// 返回空串 = 根未存,调用方应跳过去重(保守保留候选,避免误杀)。
func (s *FingerScanner) rootBodyHash(origin string) string {
	if s == nil || origin == "" {
		return ""
	}
	s.jsContextMutex.Lock()
	defer s.jsContextMutex.Unlock()
	return hashBody(s.pageContextBodies[origin])
}

// isCatchAllShell 判断候选 body 是否与根 body 相同(catch-all 网关对所有路径返回同一份壳子)。
// rootHash 为空时返回 false(根未存,无法判定,保守不算 catch-all)。
func isCatchAllShell(rootHash string, candidateBody []byte) bool {
	if rootHash == "" {
		return false
	}
	return hashBody(candidateBody) == rootHash
}

// probeContextPath 存活探测一个候选上下文路径,返回 (alive, body, isCatchAll)。
//   - alive=false     连不上/超时/404 → 死,该路径不应纳入主动指纹探测
//   - isCatchAll=true body==根 body → catch-all 壳子,同样不应纳入
//
// 注意:404 单独判死(网关对未知路径统一返 404 JSON,非 catch-all 200,body 不同于根,
// 仅靠 body 去重挡不住)。401/403/5xx 保留(可能有真实受保护/报错端点)。
func (s *FingerScanner) probeContextPath(ctx context.Context, candidateURL *url.URL) (alive bool, body []byte, isCatchAll bool) {
	if s == nil || candidateURL == nil || ctx.Err() != nil {
		return false, nil, false
	}
	resp, err := clients.DoRequest("GET", candidateURL.String(), s.headers, nil, catchAllProbeTimeout, s.client)
	if err != nil || resp == nil {
		return false, nil, false
	}
	if resp.StatusCode() == http.StatusNotFound {
		return false, nil, false
	}
	body = httputil.LimitResponseBytes(resp.Body(), maxInfoReponseSize)
	rootHash := s.rootBodyHash(contextOriginKey(candidateURL))
	return true, body, isCatchAllShell(rootHash, body)
}

// frameworkNoiseOn404Names 列出"仅凭错误页就能命中"的框架指纹。
// 这些规则原本就是为探测错误页设计的(如 SpringBoot-Framework 的 whitelabel / 404 JSON),
// 但发现的 404 子路径只是触发了框架的统一错误页,并不代表该路径真实运行此框架。
// 在 404 响应上剔除,避免每个 404 子路径都被打上框架标签形成噪声。
var frameworkNoiseOn404Names = map[string]struct{}{
	"SpringBoot-Framework": {},
}

// filterFrameworkNoiseOn404 在 404 响应上剔除"靠错误页命中的框架指纹"。
// 非 404 响应原样返回。调用方在 dedup 前调用,剔除后若列表变空,
// 已有的 KnownFingerprints 去重逻辑会把这条结果整体丢弃。
func filterFrameworkNoiseOn404(statusCode int, fingerprints []FingerprintMatch) []FingerprintMatch {
	if statusCode != http.StatusNotFound || len(fingerprints) == 0 {
		return fingerprints
	}
	filtered := make([]FingerprintMatch, 0, len(fingerprints))
	dropped := false
	for _, fp := range fingerprints {
		if _, noise := frameworkNoiseOn404Names[fp.Name]; noise {
			dropped = true
			continue
		}
		filtered = append(filtered, fp)
	}
	if !dropped {
		return fingerprints
	}
	return filtered
}

// filterCatchAllContextPaths 对一组候选上下文路径做存活 + catch-all 过滤,返回应保留的。
//   - 根 body 未存(rootBodyHash=="") → 无法判定,保守全保留(不发探测包,保持原行为)
//   - 否则并发逐个 GET:死(连不上/超时/404)或 catch-all(body==根)的丢弃
//
// 用于 JS context 这类从 JS 字符串/API 抓出来、原本无任何验活的路径:
// 晋升为主动探测 base 前先过这道关,1 次验活换掉后续 N 次必败的指纹探测。
func (s *FingerScanner) filterCatchAllContextPaths(ctx context.Context, base *url.URL, candidates []string) []string {
	if s == nil || base == nil || len(candidates) == 0 {
		return candidates
	}
	if ctx.Err() != nil {
		return candidates
	}
	if s.rootBodyHash(contextOriginKey(base)) == "" {
		// 根未扫到,无法判定 catch-all,保守全保留。
		return candidates
	}

	kept := make([]string, 0, len(candidates))
	var mu sync.Mutex
	thread := s.thread
	if thread <= 0 {
		thread = 1
	}
	type indexedResult struct {
		index int
		keep  bool
	}
	results := make([]bool, len(candidates))
	var wg sync.WaitGroup
	pool, err := ants.NewPoolWithFunc(thread, func(raw interface{}) {
		defer wg.Done()
		if ctx.Err() != nil {
			return
		}
		task := raw.(indexedResult)
		candidateURL := buildContextBaseURL(base, candidates[task.index])
		if candidateURL == nil {
			mu.Lock()
			results[task.index] = true
			mu.Unlock()
			return
		}
		alive, _, isCatchAll := s.probeContextPath(ctx, candidateURL)
		mu.Lock()
		results[task.index] = alive && !isCatchAll
		mu.Unlock()
	})
	if err != nil {
		// 池创建失败退回串行,功能不丢
		for i, c := range candidates {
			if ctx.Err() != nil {
				for _, rest := range candidates[i:] {
					kept = append(kept, rest)
				}
				break
			}
			candidateURL := buildContextBaseURL(base, c)
			if candidateURL == nil {
				kept = append(kept, c)
				continue
			}
			alive, _, isCatchAll := s.probeContextPath(ctx, candidateURL)
			if alive && !isCatchAll {
				kept = append(kept, c)
			}
		}
		return kept
	}
	defer pool.Release()

	for i := range candidates {
		if ctx.Err() != nil {
			for _, rest := range candidates[i:] {
				kept = append(kept, rest)
			}
			break
		}
		wg.Add(1)
		if err := pool.Invoke(indexedResult{index: i}); err != nil {
			results[i] = true
			wg.Done()
		}
	}
	wg.Wait()
	for i, keep := range results {
		if keep {
			kept = append(kept, candidates[i])
		}
	}
	return kept
}
