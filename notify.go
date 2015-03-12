package mobilepay

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
    // 填入支付宝公钥
	pubKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGf************************************************************
****************************************************************
****************************************************************
********************AQAB
-----END PUBLIC KEY-----`

	partner = "2088811103141914"
)

type MobilePayNotify struct {
	Notify_time         string `json:"notify_time"`
	Notify_type         string `json:"notify_type"`
	Notify_id           string `json:"notify_id"`
	Sign_type           string `json:"sign_type"`
	Sign                string `json:"sign"`
	Out_trade_no        string `json:"out_trade_no"`
	Subject             string `json:"subject"`
	Payment_type        string `json:"payment_type"`
	Trade_no            string `json:"trade_no"`
	Trade_status        string `json:"trade_status"`
	Seller_id           string `json:"seller_id"`
	Seller_email        string `json:"seller_email"`
	Buyer_id            string `json:"buyer_id"`
	Buyer_email         string `json:"buyer_email"`
	Total_fee           string `json:"total_fee"`
	Quantity            string `json:"quantity"`
	Price               string `json:"price"`
	Body                string `json:"body"`
	Gmt_create          string `json:"gmt_create"`
	Gmt_payment         string `json:"gmt_payment"`
	Is_total_fee_adjust string `json:"is_total_fee_adjust"`
	Use_coupon          string `json:"use_coupon"`
	Discount            string `json:"discount"`
	Refund_status       string `json:"refund_status"`
	Gmt_refund          string `json:"gmt_refund"`
}

func ParseParams(r *http.Request) *MobilePayNotify {
	defer r.Body.Close()
	b, _ := ioutil.ReadAll(r.Body)
	v, _ := url.ParseQuery(string(b))
	notify_params := map[string]string{}
	for k, v := range v {
		notify_params[k] = v[0]
	}
	j, _ := json.Marshal(notify_params)
	mobileNotify := new(MobilePayNotify)
	json.Unmarshal(j, mobileNotify)
	return mobileNotify
}

func (m *MobilePayNotify) signStr() string {
	paramsMap := map[string]string{}

	// 把参数解析到map里
	j, _ := json.Marshal(m)
	json.Unmarshal(j, &paramsMap)

	delete(paramsMap, "sign")
	delete(paramsMap, "sign_type")

	keys := []string{}
	for k, _ := range paramsMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var signstr string
	for _, v := range keys {
		if paramsMap[v] == "" {
			continue
		}
		signstr += "&" + v + "=" + paramsMap[v]
	}
	signstr = strings.TrimLeft(signstr, "&")
	return signstr
}

func (m *MobilePayNotify) VerifySign() (bool, error) {

	// 待签名数据
	data := m.signStr()
	// Parse public key into rsa.PublicKey
	PEMBlock, _ := pem.Decode([]byte(pubKeyPEM))
	if PEMBlock == nil {
		return false, errors.New("Could not parse Public Key PEM")
	}
	if PEMBlock.Type != "PUBLIC KEY" {
		return false, errors.New("Found wrong key type")
	}
	pubkey, err := x509.ParsePKIXPublicKey(PEMBlock.Bytes)
	if err != nil {
		return false, err
	}

	// compute the sha1
	h := sha1.New()
	h.Write([]byte(data))

	signature, err := base64.StdEncoding.DecodeString(m.Sign)
	if err != nil {
		return false, err
	}

	// Verify
	err = rsa.VerifyPKCS1v15(pubkey.(*rsa.PublicKey), crypto.SHA1, h.Sum(nil), signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

func AliReqVerify(notify_id string) bool {
	resp, err := http.Get("https://mapi.alipay.com/gateway.do?service=notify_verify&partner=" + partner + "&notify_id=" + notify_id)
	if err != nil {
		return false
	}

	defer resp.Body.Close()
	r, _ := ioutil.ReadAll(resp.Body)
	if string(r) == "true" {
		return true
	} else {
		return false
	}
}
