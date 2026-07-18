package fingers

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"

	"github.com/Knetic/govaluate"
	"gopkg.in/yaml.v2"
)

type Fingerprint struct {
	Name           string               `yaml:"name"`
	HighRisk       bool                 `yaml:"high_risk,omitempty"`
	Vendor         string               `yaml:"vendor,omitempty"`
	Description    string               `yaml:"description,omitempty"`
	Path           []string             `yaml:"path,omitempty"`
	ContextEnabled bool                 `yaml:"context_enable,omitempty"`
	Rule           []string             `yaml:"rule"`
	Vuln           bool                 `yaml:"vuln,omitempty"`
	Extract        []FingerprintExtract `yaml:"extract,omitempty"`
}

type FingerprintExtract struct {
	Name  string `yaml:"name,omitempty"`
	From  string `yaml:"from"`
	Regex string `yaml:"regex"`
}

// 指纹实体
type FingerEntity struct {
	ProductName    string
	HighRisk       bool
	AllString      string
	Description    string
	Path           []string
	ContextEnabled bool
	Rule           []RuleData
	Vuln           bool
	Extract        []FingerprintExtract
}

type RuleData struct {
	Start   int
	End     int
	Op      int16  // 0= 1!= 2== 3>= 4<= 5~=
	Key     string // body="123"中的body
	Value   string // body="123"中的123， 指纹规则大小写敏感
	ValueLC string // 指纹规则小写
	All     string // body="123"
}

type FingerprintRepository struct {
	FingerprintDB              []FingerEntity
	ActiveFingerprintDB        []FingerEntity
	ContextActiveFingerprintDB []FingerEntity
}

func LoadFingerprintFromBytes(data []byte) ([]FingerEntity, error) {
	var fps map[string][]Fingerprint
	if err := yaml.Unmarshal(data, &fps); err != nil {
		return nil, err
	}

	var result []FingerEntity

	// 获取每个组的指纹
	for _, fingers := range fps {
		// 遍历所有指纹
		for _, finger := range fingers {
			for _, rule := range finger.Rule {
				entity := FingerEntity{
					ProductName:    finger.Name,
					Rule:           ParseRule(rule),
					Description:    finger.Description,
					HighRisk:       finger.HighRisk,
					AllString:      rule,
					Path:           finger.Path,
					ContextEnabled: finger.ContextEnabled,
					Vuln:           finger.Vuln,
					Extract:        append([]FingerprintExtract(nil), finger.Extract...),
				}
				result = append(result, entity)
			}
		}
	}

	return result, nil
}

func LoadFingerprintFromFile(path string) ([]FingerEntity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadFingerprintFromBytes(data)
}

func LoadFingerprintFromFS(fsys fs.FS, name string) ([]FingerEntity, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	return LoadFingerprintFromBytes(data)
}

func BuildFingerprintRepository(fingers []FingerEntity) *FingerprintRepository {
	result := make([]FingerEntity, len(fingers))
	copy(result, fingers)

	var active []FingerEntity
	var contextActive []FingerEntity
	for _, entity := range result {
		if len(entity.Path) > 0 {
			active = append(active, entity)
			if entity.ContextEnabled {
				contextActive = append(contextActive, entity)
			}
		}
	}

	return &FingerprintRepository{
		FingerprintDB:              result,
		ActiveFingerprintDB:        active,
		ContextActiveFingerprintDB: contextActive,
	}
}

func (r *FingerprintRepository) GetFingerprintDB() []FingerEntity {
	result := make([]FingerEntity, len(r.FingerprintDB))
	copy(result, r.FingerprintDB)
	return result
}

func (r *FingerprintRepository) GetActiveFingerprintDB() []FingerEntity {
	result := make([]FingerEntity, len(r.ActiveFingerprintDB))
	copy(result, r.ActiveFingerprintDB)
	return result
}

func (r *FingerprintRepository) GetContextActiveFingerprintDB() []FingerEntity {
	result := make([]FingerEntity, len(r.ContextActiveFingerprintDB))
	copy(result, r.ContextActiveFingerprintDB)
	return result
}

func ParseRule(rule string) []RuleData {
	var result []RuleData
	empty := RuleData{}

	for {
		data := getRuleData(rule)
		if data == empty {
			break
		}
		result = append(result, data)
		rule = rule[:data.Start] + "T" + rule[data.End:]
	}
	return result
}

func getRuleData(rule string) RuleData {
	if !strings.Contains(rule, "=\"") {
		return RuleData{}
	}
	pos := strings.Index(rule, "=\"")
	op := 0
	switch rule[pos-1] {
	case 33: // !
		op = 1 // !=
	case 61: // =
		op = 2 // ==
	case 62: // >
		op = 3 // >=
	case 60: // <
		op = 4 // <=
	case 126: // ~
		op = 5 // ~=
	}

	start := 0
	ti := 0
	if op > 0 {
		ti = 1
	}
	for i := pos - 1 - ti; i >= 0; i-- {
		if !isRuleKeyChar(rule[i]) {
			start = i + 1
			break
		}
	}
	key := rule[start : pos-ti]

	end := pos + 2
	for i := pos + 2; i < len(rule)-1; i++ {
		if rule[i] != 92 && rule[i+1] == 34 {
			end = i + 2
			break
		}
	}
	// 增加错误判断，防止切片越界
	if end-1 > len(rule) || pos+2 > len(rule) || end-1 < pos+2 {
		fmt.Printf("Error: rule [%s] pos [%d] end [%d] len [%d]\n", rule, pos, end, len(rule))
		return RuleData{}
	}
	value := rule[pos+2 : end-1]
	all := rule[start:end]
	valueLc := strings.ToLower(value)
	valueLc = strings.ReplaceAll(valueLc, "\\\"", "\"")
	return RuleData{Start: start, End: end, Op: int16(op), Key: key, Value: value, ValueLC: valueLc, All: all}
}

func isRuleKeyChar(char byte) bool {
	return (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '_'
}

// 将 T/F 替换为 true/false，并转换逻辑运算符符号
func normalizeExpression(expr string) string {
	expr = strings.ReplaceAll(expr, " ", "") // 去空格
	expr = strings.ReplaceAll(expr, "T", "true")
	expr = strings.ReplaceAll(expr, "F", "false")
	return expr
}

// 使用 govaluate 实现 boolEval
func boolEval(expression string) (bool, error) {
	// 检查是否有 T 或 F
	if !strings.Contains(expression, "T") && !strings.Contains(expression, "F") {
		return false, errors.New("纯布尔表达式错误，没有包含T/F")
	}

	// 标准化表达式
	exprStr := normalizeExpression(expression)

	// 创建表达式对象
	expr, err := govaluate.NewEvaluableExpression(exprStr)
	if err != nil {
		return false, fmt.Errorf("无法解析表达式 [%s]: %v", exprStr, err)

	}

	// 求值
	result, err := expr.Evaluate(nil) // 不需要变量
	if err != nil {
		return false, fmt.Errorf("执行表达式出错 [%s]: %v", exprStr, err)
	}

	// 类型断言并返回布尔结果
	if booleanResult, ok := result.(bool); ok {
		return booleanResult, nil
	}
	return false, errors.New("结果不是布尔类型")
}

func regexMatch(pattern string, s string) (bool, error) {
	matched, err := regexp.MatchString(pattern, s)
	if err != nil {
		return false, err
	}
	return matched, nil
}

// body="123"  op=0  dataSource为http.body dataRule=123
func dataCheckString(op int16, dataSource string, dataRule string) bool {
	if dataSource == "" {
		return false
	}
	dataRule = strings.ReplaceAll(dataRule, "\\\"", "\"")
	switch op {
	case 0:
		if strings.Contains(dataSource, dataRule) {
			return true
		}
	case 1:
		if !strings.Contains(dataSource, dataRule) {
			return true
		}
	case 2:
		if dataSource == dataRule {
			return true
		}
	case 5:
		rs, err := regexMatch(dataRule, dataSource)
		if err == nil && rs {
			return true
		}
	}
	return false
}

func dataCheckInt(op int16, dataSource int, dataRule int) bool {
	switch op {
	// 数字相等
	case 0:
		if dataSource == dataRule {
			return true
		}
	// 数字不相等
	case 1:
		if dataSource != dataRule {
			return true
		}
	// 数字精确相等
	case 2:
		if dataSource == dataRule {
			return true
		}
	// 大于等于
	case 3:
		if dataSource >= dataRule {
			return true
		}
	case 4:
		if dataSource <= dataRule {
			return true
		}
	}
	return false
}
