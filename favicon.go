package fingers

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/qiwentaidi/clients"
	arrayutil "github.com/qiwentaidi/utils/array"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-resty/resty/v2"
	"github.com/twmb/murmur3"
)

var (
	iconDesktopRels = []string{"icon", "shortcut icon"}         // 桌面端 Logo 优先匹配
	iconMobileRels  = []string{"apple-touch-icon", "mask-icon"} // 移动｜其他端 Logo 其次
)

// FaviconResult favicon处理结果
type FaviconResult struct {
	Mmh3Hash string // mmh3 hash值
	Md5Hash  string // md5 hash值
	FilePath string // 本地存储路径
}

// 获取favicon Mmh3Hash32 和 MD5值
func FaviconHash(u *url.URL, headers map[string]string, client *resty.Client) (string, string) {
	result := getFaviconWithStorage(u, headers, client, noopStore{})
	return result.Mmh3Hash, result.Md5Hash
}

// GetFaviconWithStorage 获取favicon并保存到本地，返回hash值和文件路径
func getFaviconWithStorage(u *url.URL, headers map[string]string, client *resty.Client, store assetStore) FaviconResult {
	result := FaviconResult{}

	resp, err := clients.DoRequest("GET", u.String(), headers, nil, 10, client)
	if err != nil {
		return result
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	if err != nil {
		return result
	}
	iconLink := parseIcons(doc)[0]
	var finalLink string
	// 如果是完整的链接，则直接请求
	if strings.HasPrefix(iconLink, "http") {
		finalLink = iconLink
		// 如果为 // 开头采用与网站同协议
	} else if strings.HasPrefix(iconLink, "//") {
		finalLink = u.Scheme + ":" + iconLink
	} else {
		finalLink = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, iconLink)
	}
	resp, err = clients.DoRequest("GET", finalLink, headers, nil, 10, client)
	if err == nil && resp.StatusCode() == 200 {
		body := resp.Body()
		hasher := md5.New()
		hasher.Write(body)
		sum := hasher.Sum(nil)
		result.Mmh3Hash = Mmh3Hash32(body)
		result.Md5Hash = hex.EncodeToString(sum)

		// 保存favicon到本地，传递favicon URL用于提取扩展名
		filePath, saveErr := saveFavicon(u.String(), finalLink, body, store)
		if saveErr == nil {
			result.FilePath = filePath
		}
	}
	return result
}

// saveFavicon 保存favicon到本地文件
// urlStr: 网站URL，用于生成文件名
// faviconURL: favicon的实际URL，用于提取扩展名
// data: favicon文件内容
func saveFavicon(urlStr string, faviconURL string, data []byte, store assetStore) (string, error) {
	// 根据favicon URL提取扩展名
	ext := getExtensionFromURL(faviconURL)

	// 定义文件名
	filename := renameOutput(urlStr) + ext
	location, err := store.Save(context.Background(), filepath.ToSlash(filename), data)
	if err != nil {
		return "", errors.New("无法保存favicon: " + err.Error())
	}
	return location, nil
}

// getExtensionFromURL 从URL中提取文件扩展名
func getExtensionFromURL(faviconURL string) string {
	// 解析URL
	u, err := url.Parse(faviconURL)
	if err != nil {
		return ".ico"
	}

	// 获取路径部分
	path := u.Path

	// 移除查询参数影响（虽然已经通过url.Parse处理了）
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx]
	}

	// 获取扩展名
	ext := strings.ToLower(filepath.Ext(path))

	// 验证是否为有效的图片扩展名
	switch ext {
	case ".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp":
		return ext
	default:
		// 默认返回 .ico
		return ".ico"
	}
}

func GetFaviconFullLink(u *url.URL, client *resty.Client) (string, error) {
	resp, err := clients.SimpleGet(u.String(), client)
	if err != nil {
		return "", err
	}
	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))
	if err != nil {
		return "", errors.New("goquery failed to parse " + u.String() + " content")
	}
	iconLink := parseIcons(doc)[0]
	var finalLink string
	// 如果是完整的链接，则直接请求
	if strings.HasPrefix(iconLink, "http") {
		finalLink = iconLink
		// 如果为 // 开头采用与网站同协议
	} else if strings.HasPrefix(iconLink, "//") {
		finalLink = u.Scheme + ":" + iconLink
	} else {
		// 传入二级路径的时，需要正确处理图标路径
		if u.Path != "" {
			finalLink = fmt.Sprintf("%s://%s%s/%s", u.Scheme, u.Host, u.Path, iconLink)
		} else {
			finalLink = fmt.Sprintf("%s://%s/%s", u.Scheme, u.Host, iconLink)
		}
	}
	return finalLink, nil
}

// parseIcons 解析HTML文档head中的<link>标签中rel属性包含icon信息的href链接
func parseIcons(doc *goquery.Document) []string {
	var icons []string
	// 桌面端
	doc.Find("head link").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if exists {
			// 匹配ICON链接
			if rel, exists := s.Attr("rel"); exists && arrayutil.ArrayContains(rel, iconDesktopRels) {
				icons = append(icons, href)
			}
		}
	})
	// 移动端
	if len(icons) == 0 {
		doc.Find("head link").Each(func(i int, s *goquery.Selection) {
			href, exists := s.Attr("href")
			if exists {
				// 匹配ICON链接
				if rel, exists := s.Attr("rel"); exists && arrayutil.ArrayContains(rel, iconMobileRels) {
					icons = append(icons, href)
				}
			}
		})
	}

	// 找不到自定义icon链接就使用默认的favicon地址
	if len(icons) == 0 {
		icons = append(icons, "favicon.ico")
	}

	return icons
}

// Reference: https://github.com/Becivells/iconhash

// Mmh3Hash32 计算 mmh3 hash
func Mmh3Hash32(raw []byte) string {
	var h32 hash.Hash32 = murmur3.New32()
	_, err := h32.Write(base64Encode(raw))
	if err == nil {
		return fmt.Sprint(int32(h32.Sum32()))
	} else {
		return "0"
	}
}

// base64 encode
func base64Encode(braw []byte) []byte {
	bckd := base64.StdEncoding.EncodeToString(braw)
	var buffer bytes.Buffer
	for i := 0; i < len(bckd); i++ {
		ch := bckd[i]
		buffer.WriteByte(ch)
		if (i+1)%76 == 0 {
			buffer.WriteByte('\n')
		}
	}
	buffer.WriteByte('\n')
	return buffer.Bytes()
}
