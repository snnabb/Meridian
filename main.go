package main

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"

	"meridian/web"
)

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// UA Profiles 闂?only 3 modes
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
type UAProfile struct {
	Name      string `json:"name"`
	UserAgent string `json:"user_agent"`
	Client    string `json:"client"`
}

var uaProfiles = map[string]UAProfile{
	"infuse": {Name: "Infuse", UserAgent: "Infuse/7.8.1", Client: "Infuse"},
	"web":    {Name: "Web", UserAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Emby Theater", Client: "Emby Web"},
	"client": {Name: "Client", UserAgent: "Emby-Theater/4.7.0", Client: "Emby Theater"},
}

func getUAProfile(mode string) UAProfile {
	if p, ok := uaProfiles[strings.ToLower(mode)]; ok {
		return p
	}
	return uaProfiles["infuse"]
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// JWT helpers (simple HMAC-SHA256)
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
var jwtSecret []byte
var jwtSecretEphemeral bool

func init() {
	var err error
	jwtSecret, jwtSecretEphemeral, err = resolveJWTSecret(os.Getenv("JWT_SECRET"))
	if err != nil {
		panic(err)
	}
}

func resolveJWTSecret(value string) ([]byte, bool, error) {
	if value != "" {
		return []byte(value), false, nil
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, false, fmt.Errorf("generate JWT secret: %w", err)
	}
	return secret, true, nil
}

// Minimal JWT 闂?no external dependency
func generateToken(userID int64, username string) (string, error) {
	header := base64url([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, err := json.Marshal(struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}{
		Sub:  userID,
		Name: username,
		Exp:  time.Now().Add(72 * time.Hour).Unix(),
	})
	if err != nil {
		return "", err
	}
	payloadEnc := base64url(payload)
	sig := hmacSHA256(header+"."+payloadEnc, jwtSecret)
	return header + "." + payloadEnc + "." + sig, nil
}

func validateToken(token string) (int64, string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0, "", fmt.Errorf("invalid token")
	}
	expectedSig := hmacSHA256(parts[0]+"."+parts[1], jwtSecret)
	if parts[2] != expectedSig {
		return 0, "", fmt.Errorf("invalid signature")
	}
	payload, err := base64urlDecode(parts[1])
	if err != nil {
		return 0, "", err
	}
	var claims struct {
		Sub  int64  `json:"sub"`
		Name string `json:"name"`
		Exp  int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, "", err
	}
	if time.Now().Unix() > claims.Exp {
		return 0, "", fmt.Errorf("token expired")
	}
	return claims.Sub, claims.Name, nil
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Crypto helpers
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?

func hmacSHA256(data string, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return base64url(h.Sum(nil))
}

func base64url(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

func base64urlDecode(s string) ([]byte, error) {
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Database
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
type DB struct {
	db *sql.DB
}

func openDB(path string) (*DB, error) {
	sqlDB, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, err
	}
	sqlDB.SetMaxOpenConns(1)
	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DB) Close() { d.db.Close() }

func (d *DB) migrate() error {
	_, err := d.db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS sites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		listen_port INTEGER NOT NULL UNIQUE,
		target_url TEXT NOT NULL,
		playback_target_url TEXT NOT NULL DEFAULT '',
		ua_mode TEXT DEFAULT 'infuse',
		enabled INTEGER DEFAULT 1,
		traffic_quota BIGINT DEFAULT 0,
		traffic_used BIGINT DEFAULT 0,
		speed_limit INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE IF NOT EXISTS traffic_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
		bytes_in BIGINT DEFAULT 0,
		bytes_out BIGINT DEFAULT 0,
		recorded_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_traffic_site_time ON traffic_logs(site_id, recorded_at);
	`)
	if err != nil {
		return err
	}

	var hasPlaybackTargetColumn int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM pragma_table_info('sites') WHERE name='playback_target_url'").Scan(&hasPlaybackTargetColumn); err != nil {
		return err
	}
	if hasPlaybackTargetColumn == 0 {
		if _, err := d.db.Exec("ALTER TABLE sites ADD COLUMN playback_target_url TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
	}

	var hasHourlyIndex int
	if err := d.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_traffic_site_hour'").Scan(&hasHourlyIndex); err != nil {
		return err
	}
	if hasHourlyIndex > 0 {
		return nil
	}

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`
		CREATE TABLE traffic_logs_dedup (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
			bytes_in BIGINT DEFAULT 0,
			bytes_out BIGINT DEFAULT 0,
			recorded_at DATETIME NOT NULL
		);
	`); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		INSERT INTO traffic_logs_dedup (site_id, bytes_in, bytes_out, recorded_at)
		SELECT site_id, SUM(bytes_in), SUM(bytes_out), recorded_at
		FROM traffic_logs
		GROUP BY site_id, recorded_at;
	`); err != nil {
		return err
	}

	if _, err := tx.Exec(`
		DELETE FROM traffic_logs;
		INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
		SELECT site_id, bytes_in, bytes_out, recorded_at
		FROM traffic_logs_dedup;
		DROP TABLE traffic_logs_dedup;
		CREATE UNIQUE INDEX idx_traffic_site_hour ON traffic_logs(site_id, recorded_at);
	`); err != nil {
		return err
	}

	return tx.Commit()
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Models
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
type Site struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	ListenPort        int    `json:"listen_port"`
	TargetURL         string `json:"target_url"`
	PlaybackTargetURL string `json:"playback_target_url"`
	UAMode            string `json:"ua_mode"`
	Enabled           bool   `json:"enabled"`
	TrafficQuota      int64  `json:"traffic_quota"`
	TrafficUsed       int64  `json:"traffic_used"`
	SpeedLimit        int    `json:"speed_limit"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

type TrafficLog struct {
	ID         int64  `json:"id"`
	SiteID     int64  `json:"site_id"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	RecordedAt string `json:"recorded_at"`
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// DB operations
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
func (d *DB) UserCount() int {
	var n int
	d.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n
}

func (d *DB) CreateUser(username, password string) (int64, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	res, err := d.db.Exec("INSERT INTO users (username, password_hash) VALUES (?, ?)", username, string(hash))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (d *DB) VerifyUser(username, password string) (int64, error) {
	var id int64
	var hash string
	err := d.db.QueryRow("SELECT id, password_hash FROM users WHERE username=?", username).Scan(&id, &hash)
	if err != nil {
		return 0, fmt.Errorf("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return 0, fmt.Errorf("invalid password")
	}
	return id, nil
}

func (d *DB) ListSites() ([]Site, error) {
	rows, err := d.db.Query("SELECT id, name, listen_port, target_url, playback_target_url, ua_mode, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sites []Site
	for rows.Next() {
		var s Site
		var enabled int
		rows.Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.PlaybackTargetURL, &s.UAMode, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
		s.Enabled = enabled == 1
		sites = append(sites, s)
	}
	if sites == nil {
		sites = []Site{}
	}
	return sites, nil
}

func (d *DB) GetSite(id int64) (*Site, error) {
	var s Site
	var enabled int
	err := d.db.QueryRow("SELECT id, name, listen_port, target_url, playback_target_url, ua_mode, enabled, traffic_quota, traffic_used, speed_limit, created_at, updated_at FROM sites WHERE id=?", id).
		Scan(&s.ID, &s.Name, &s.ListenPort, &s.TargetURL, &s.PlaybackTargetURL, &s.UAMode, &enabled, &s.TrafficQuota, &s.TrafficUsed, &s.SpeedLimit, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Enabled = enabled == 1
	return &s, nil
}

func (d *DB) CreateSite(name string, port int, targetURL, playbackTargetURL, uaMode string, quota int64, speedLimit int) (*Site, error) {
	res, err := d.db.Exec(
		"INSERT INTO sites (name, listen_port, target_url, playback_target_url, ua_mode, traffic_quota, speed_limit) VALUES (?,?,?,?,?,?,?)",
		name, port, targetURL, playbackTargetURL, uaMode, quota, speedLimit,
	)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return d.GetSite(id)
}

func (d *DB) UpdateSite(id int64, name string, port int, targetURL, playbackTargetURL, uaMode string, quota int64, speedLimit int) error {
	_, err := d.db.Exec(
		"UPDATE sites SET name=?, listen_port=?, target_url=?, playback_target_url=?, ua_mode=?, traffic_quota=?, speed_limit=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		name, port, targetURL, playbackTargetURL, uaMode, quota, speedLimit, id,
	)
	return err
}

func (d *DB) DeleteSite(id int64) error {
	tx, _ := d.db.Begin()
	tx.Exec("DELETE FROM traffic_logs WHERE site_id=?", id)
	tx.Exec("DELETE FROM sites WHERE id=?", id)
	return tx.Commit()
}

func (d *DB) ToggleSite(id int64) (bool, error) {
	var enabled int
	d.db.QueryRow("SELECT enabled FROM sites WHERE id=?", id).Scan(&enabled)
	newVal := 1 - enabled
	_, err := d.db.Exec("UPDATE sites SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", newVal, id)
	return newVal == 1, err
}

func (d *DB) AddTraffic(siteID, bytesIn, bytesOut int64) {
	if err := d.addTraffic(siteID, bytesIn, bytesOut); err != nil {
		log.Printf("[traffic] failed to persist usage for site %d: %v", siteID, err)
	}
}

func (d *DB) addTraffic(siteID, bytesIn, bytesOut int64) error {
	hour := time.Now().Truncate(time.Hour).Format("2006-01-02 15:04:05")
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(
		`INSERT INTO traffic_logs (site_id, bytes_in, bytes_out, recorded_at)
		 VALUES (?,?,?,?)
		 ON CONFLICT(site_id, recorded_at) DO UPDATE SET
		 	bytes_in = traffic_logs.bytes_in + excluded.bytes_in,
		 	bytes_out = traffic_logs.bytes_out + excluded.bytes_out`,
		siteID, bytesIn, bytesOut, hour,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(
		"UPDATE sites SET traffic_used=traffic_used+?+?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
		bytesIn, bytesOut, siteID,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (d *DB) GetTrafficLogs(siteID int64, hours int) ([]TrafficLog, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour).Format("2006-01-02 15:04:05")
	rows, err := d.db.Query(
		"SELECT id, site_id, bytes_in, bytes_out, recorded_at FROM traffic_logs WHERE site_id=? AND recorded_at>=? ORDER BY recorded_at",
		siteID, since,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var logs []TrafficLog
	for rows.Next() {
		var l TrafficLog
		rows.Scan(&l.ID, &l.SiteID, &l.BytesIn, &l.BytesOut, &l.RecordedAt)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []TrafficLog{}
	}
	return logs, nil
}

func (d *DB) DashboardStats() map[string]interface{} {
	var total, online int
	d.db.QueryRow("SELECT COUNT(*) FROM sites").Scan(&total)
	d.db.QueryRow("SELECT COUNT(*) FROM sites WHERE enabled=1").Scan(&online)
	var totalTraffic int64
	d.db.QueryRow("SELECT COALESCE(SUM(traffic_used),0) FROM sites").Scan(&totalTraffic)
	return map[string]interface{}{
		"total_sites":   total,
		"online_sites":  online,
		"total_traffic": totalTraffic,
	}
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Proxy Engine
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
var embyAuthClientRe = regexp.MustCompile(`(?i)(Client=")[^"]*"`)

type ProxyInstance struct {
	Site             Site
	server           *http.Server
	listener         net.Listener
	bytesIn          atomic.Int64
	bytesOut         atomic.Int64
	reqCount         atomic.Int64
	persistedTraffic atomic.Int64
}

type ProxyManager struct {
	mu       sync.RWMutex
	proxies  map[int64]*ProxyInstance
	database *DB
}

func NewProxyManager(db *DB) *ProxyManager {
	return &ProxyManager{
		proxies:  make(map[int64]*ProxyInstance),
		database: db,
	}
}

// metered response writer
type meteredWriter struct {
	http.ResponseWriter
	written *atomic.Int64
}

func (m *meteredWriter) Write(b []byte) (int, error) {
	n, err := m.ResponseWriter.Write(b)
	m.written.Add(int64(n))
	return n, err
}

// Flush support for streaming
func (m *meteredWriter) Flush() {
	if f, ok := m.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack support for WebSocket upgrade
func (m *meteredWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := m.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// metered request body reader
type meteredReader struct {
	io.ReadCloser
	read *atomic.Int64
}

func (m *meteredReader) Read(p []byte) (int, error) {
	n, err := m.ReadCloser.Read(p)
	m.read.Add(int64(n))
	return n, err
}

// 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?Rate-limited writer (token bucket) 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?
type rateLimitedWriter struct {
	http.ResponseWriter
	bytesPerSec int64
	written     *atomic.Int64
	start       time.Time
}

func (w *rateLimitedWriter) Write(b []byte) (int, error) {
	if w.bytesPerSec <= 0 {
		n, err := w.ResponseWriter.Write(b)
		w.written.Add(int64(n))
		return n, err
	}
	totalWritten := 0
	for len(b) > 0 {
		elapsed := time.Since(w.start).Seconds()
		if elapsed < 0.001 {
			elapsed = 0.001
		}
		allowed := int64(elapsed*float64(w.bytesPerSec)) - w.written.Load()
		if allowed <= 0 {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		chunk := b
		if int64(len(chunk)) > allowed {
			chunk = b[:allowed]
		}
		n, err := w.ResponseWriter.Write(chunk)
		w.written.Add(int64(n))
		totalWritten += n
		b = b[n:]
		if err != nil {
			return totalWritten, err
		}
	}
	return totalWritten, nil
}

func (w *rateLimitedWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *rateLimitedWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, fmt.Errorf("hijack not supported")
}

// 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?WebSocket tunnel 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}

func normalizeTargetURL(addr string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("target URL is required")
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	parsed, err := url.Parse(addr)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid target URL")
	}
	return parsed, nil
}

func isPlaybackRequest(path string) bool {
	path = strings.ToLower(path)
	switch {
	case strings.HasPrefix(path, "/videos/"),
		strings.HasPrefix(path, "/emby/videos/"),
		strings.HasPrefix(path, "/audio/"),
		strings.HasPrefix(path, "/emby/audio/"),
		strings.HasPrefix(path, "/livetv/"),
		strings.HasPrefix(path, "/emby/livetv/"):
		return true
	case strings.HasPrefix(path, "/items/"),
		strings.HasPrefix(path, "/emby/items/"):
		return strings.Contains(path, "/download") || strings.Contains(path, "/file")
	default:
		return false
	}
}

func upstreamTargetForRequest(r *http.Request, apiTarget, playbackTarget *url.URL) *url.URL {
	if playbackTarget != nil && isPlaybackRequest(r.URL.Path) {
		return playbackTarget
	}
	return apiTarget
}

func applyUAProfileHeaders(header http.Header, profile UAProfile) {
	header.Set("User-Agent", profile.UserAgent)
	if auth := header.Get("X-Emby-Authorization"); auth != "" {
		if embyAuthClientRe.MatchString(auth) {
			auth = embyAuthClientRe.ReplaceAllString(auth, `${1}`+profile.Client+`"`)
		}
		header.Set("X-Emby-Authorization", auth)
	}
	if auth := header.Get("Authorization"); auth != "" {
		if embyAuthClientRe.MatchString(auth) {
			auth = embyAuthClientRe.ReplaceAllString(auth, `${1}`+profile.Client+`"`)
		}
		header.Set("Authorization", auth)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request, target *url.URL, profile UAProfile, inst *ProxyInstance) {
	// Build target WS URL
	scheme := "ws"
	if target.Scheme == "https" {
		scheme = "wss"
	}
	targetURL := scheme + "://" + target.Host + r.URL.RequestURI()

	// Hijack client connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket not supported", 500)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		log.Printf("[WS] hijack error: %v", err)
		return
	}
	defer clientConn.Close()

	// Connect to upstream
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	var upstreamConn net.Conn
	host := target.Host
	if !strings.Contains(host, ":") {
		if scheme == "wss" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	if scheme == "wss" {
		upstreamConn, err = tls.DialWithDialer(dialer, "tcp", host, &tls.Config{InsecureSkipVerify: true})
	} else {
		upstreamConn, err = dialer.Dial("tcp", host)
	}
	if err != nil {
		log.Printf("[WS] upstream dial error: %v", err)
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstreamConn.Close()

	// Send upgrade request to upstream
	reqLine := fmt.Sprintf("%s %s HTTP/1.1\r\n", r.Method, r.URL.RequestURI())
	upstreamConn.Write([]byte(reqLine))
	r.Header.Set("Host", target.Host)
	applyUAProfileHeaders(r.Header, profile)
	r.Header.Write(upstreamConn)
	upstreamConn.Write([]byte("\r\n"))

	_ = targetURL
	log.Printf("[WS] tunnel established: client <-> %s", target.Host)

	// Bidirectional copy
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstreamConn, clientBuf)
		inst.bytesIn.Add(n)
		done <- struct{}{}
	}()
	go func() {
		n, _ := io.Copy(clientConn, upstreamConn)
		inst.bytesOut.Add(n)
		done <- struct{}{}
	}()
	<-done
}

func (pm *ProxyManager) StartSite(site Site) error {
	target, err := normalizeTargetURL(site.TargetURL)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}
	var playbackTarget *url.URL
	if strings.TrimSpace(site.PlaybackTargetURL) != "" {
		playbackTarget, err = normalizeTargetURL(site.PlaybackTargetURL)
		if err != nil {
			return fmt.Errorf("invalid playback target URL: %w", err)
		}
	}

	profile := getUAProfile(site.UAMode)
	inst := &ProxyInstance{Site: site}
	inst.persistedTraffic.Store(site.TrafficUsed)

	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			upstream := upstreamTargetForRequest(req, target, playbackTarget)
			req.URL.Scheme = upstream.Scheme
			req.URL.Host = upstream.Host
			req.Host = upstream.Host
			applyUAProfileHeaders(req.Header, profile)
		},
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("X-Frame-Options")
			resp.Header.Del("Content-Security-Policy")
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("[%s] proxy error: %v", site.Name, err)
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte(`{"error":"upstream unavailable"}`))
		},
	}

	// Speed limit in bytes/sec (field is in Mbps, 0 = unlimited)
	speedLimitBytes := int64(site.SpeedLimit) * 125000 // Mbps -> bytes/sec

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inst.reqCount.Add(1)

		// 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?Traffic quota check 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?
		if site.TrafficQuota > 0 {
			currentUsed := inst.persistedTraffic.Load() + inst.bytesIn.Load() + inst.bytesOut.Load()
			if currentUsed >= site.TrafficQuota {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"濠电姷鏁告慨鐑藉极閹间礁纾婚柣鏃傚劋瀹曞弶绻濋棃娑氬妞ゆ劘濮ら幈銊ノ熼幐搴ｃ€愰梻鍌氬亞閸ㄥ爼寮婚敐澶婄闁绘垵娲ら崣鏇犵磽娴ｇ懓鏁剧紒鎻掑⒔閹广垹鈹戠€ｎ偒妫冨┑鐐村灦閻燁垰螞閻愬樊娓婚柕鍫濇閻撱儵鏌ㄩ弴顏嗙暤闁糕斁鍋撳銈嗗笒閸犳艾顭囬幇鐗堢厽闁斥晛鍟粈鍫澝瑰鍜佺劸闁宠閰ｉ獮姗€鎼归銈傚亾椤掑嫭鈷戦梻鍫熺〒婢ф洘绻涚拠褏绉柟?}`))
				return
			}
		}

		// 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?WebSocket upgrade 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?
		if isWebSocketUpgrade(r) {
			handleWebSocket(w, r, upstreamTargetForRequest(r, target, playbackTarget), profile, inst)
			return
		}

		// 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?Normal proxy with metering 闂傚倸鍊搁崐椋庣矆娓氣偓瀹曨垶宕稿Δ鈧崒銊︾節婵犲倻澧曠痪鎯ь煼閺岀喖宕滆鐢盯鏌ｉ幘鍐叉殻闁哄本绋栫粻娑㈠箼閸愨敩锔界箾?
		if r.Body != nil {
			r.Body = &meteredReader{ReadCloser: r.Body, read: &inst.bytesIn}
		}

		var rw http.ResponseWriter
		if speedLimitBytes > 0 {
			rw = &rateLimitedWriter{
				ResponseWriter: w,
				bytesPerSec:    speedLimitBytes,
				written:        &inst.bytesOut,
				start:          time.Now(),
			}
		} else {
			rw = &meteredWriter{ResponseWriter: w, written: &inst.bytesOut}
		}
		proxy.ServeHTTP(rw, r)
	})

	listenAddr := fmt.Sprintf(":%d", site.ListenPort)
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", listenAddr, err)
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	inst.server = server
	inst.listener = listener

	pm.mu.Lock()
	if existing, ok := pm.proxies[site.ID]; ok {
		if existing.server != nil {
			existing.server.Close()
		}
		delete(pm.proxies, site.ID)
	}
	pm.proxies[site.ID] = inst
	pm.mu.Unlock()

	go func() {
		if playbackTarget != nil {
			log.Printf("[%s] proxy :%d -> %s (playback: %s, UA: %s)", site.Name, site.ListenPort, site.TargetURL, site.PlaybackTargetURL, site.UAMode)
		} else {
			log.Printf("[%s] proxy :%d -> %s (UA: %s)", site.Name, site.ListenPort, site.TargetURL, site.UAMode)
		}
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("[%s] server error: %v", site.Name, err)
		}
	}()

	return nil
}

func (pm *ProxyManager) StopSite(id int64) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if inst, ok := pm.proxies[id]; ok {
		pm.flushProxyTraffic(inst)
		if inst.server != nil {
			inst.server.Close()
		}
		delete(pm.proxies, id)
	}
}

func (pm *ProxyManager) IsRunning(id int64) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	_, ok := pm.proxies[id]
	return ok
}

func (pm *ProxyManager) StartAllEnabled() {
	sites, _ := pm.database.ListSites()
	for _, s := range sites {
		if s.Enabled {
			if err := pm.StartSite(s); err != nil {
				log.Printf("[%s] failed to start: %v", s.Name, err)
			}
		}
	}
}

// Flush traffic counters to DB periodically
func (pm *ProxyManager) FlushTraffic() {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	for _, inst := range pm.proxies {
		pm.flushProxyTraffic(inst)
	}
}

func (pm *ProxyManager) flushProxyTraffic(inst *ProxyInstance) {
	in := inst.bytesIn.Swap(0)
	out := inst.bytesOut.Swap(0)
	if in == 0 && out == 0 {
		return
	}
	if err := pm.database.addTraffic(inst.Site.ID, in, out); err != nil {
		inst.bytesIn.Add(in)
		inst.bytesOut.Add(out)
		log.Printf("[%s] failed to flush traffic: %v", inst.Site.Name, err)
		return
	}
	delta := in + out
	inst.persistedTraffic.Add(delta)
	inst.Site.TrafficUsed += delta
}

func (pm *ProxyManager) GetRunningCount() int {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	return len(pm.proxies)
}

// GracefulShutdown stops all proxies gracefully
func (pm *ProxyManager) GracefulShutdown(ctx context.Context) {
	pm.FlushTraffic()
	pm.mu.Lock()
	defer pm.mu.Unlock()
	for id, inst := range pm.proxies {
		log.Printf("[%s] shutting down...", inst.Site.Name)
		inst.server.Shutdown(ctx)
		delete(pm.proxies, id)
	}
}

// GetTotalRequests returns total request count across all proxies
func (pm *ProxyManager) GetTotalRequests() int64 {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	var total int64
	for _, inst := range pm.proxies {
		total += inst.reqCount.Load()
	}
	return total
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Diagnostics
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
type DiagResult struct {
	Health  DiagHealth  `json:"health"`
	TLS     DiagTLS     `json:"tls"`
	Headers DiagHeaders `json:"headers"`
	Proxy   DiagProxy   `json:"proxy"`
}

type DiagHealth struct {
	Status    string `json:"status"` // online, offline, error
	EmbyVer   string `json:"emby_version"`
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

type DiagTLS struct {
	Enabled   bool   `json:"enabled"`
	Valid     bool   `json:"valid"`
	Issuer    string `json:"issuer"`
	ExpiresAt string `json:"expires_at"`
	DaysLeft  int    `json:"days_left"`
	Error     string `json:"error,omitempty"`
}

type DiagHeaders struct {
	UAApplied   bool   `json:"ua_applied"`
	CurrentUA   string `json:"current_ua"`
	ClientField string `json:"client_field"`
}

type DiagProxy struct {
	Running    bool   `json:"running"`
	ListenPort int    `json:"listen_port"`
	TotalReqs  int64  `json:"total_requests"`
	Uptime     string `json:"uptime,omitempty"`
}

func tlsIssuerName(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	if cert.Issuer.CommonName != "" {
		return cert.Issuer.CommonName
	}
	return cert.Issuer.String()
}

func healthProbeURLs(target *url.URL) []string {
	basePath := strings.TrimSpace(target.Path)
	var suffixes []string
	if basePath == "" || basePath == "/" {
		suffixes = []string{"System/Info/Public", "emby/System/Info/Public", ""}
	} else {
		suffixes = []string{"System/Info/Public", ""}
	}

	seen := map[string]struct{}{}
	urls := make([]string, 0, len(suffixes))
	for _, suffix := range suffixes {
		probe := *target
		probe.RawQuery = ""
		probe.Fragment = ""
		if suffix == "" {
			cleanPath := path.Clean("/" + strings.Trim(basePath, "/"))
			if cleanPath == "." || cleanPath == "" {
				cleanPath = "/"
			}
			probe.Path = cleanPath
		} else {
			probe.Path = path.Clean("/" + path.Join(strings.Trim(basePath, "/"), suffix))
		}
		if _, ok := seen[probe.String()]; ok {
			continue
		}
		seen[probe.String()] = struct{}{}
		urls = append(urls, probe.String())
	}
	return urls
}

func probeSiteHealth(targetURL string) DiagHealth {
	target, err := normalizeTargetURL(targetURL)
	if err != nil {
		return DiagHealth{Status: "offline", Error: err.Error()}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	reachable := false
	var reachableLatency int64
	var serverError string
	var serverErrorLatency int64

	for _, probeURL := range healthProbeURLs(target) {
		start := time.Now()
		resp, err := client.Get(probeURL)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			return DiagHealth{Status: "offline", LatencyMs: latency, Error: err.Error()}
		}

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode >= 500 {
			serverError = fmt.Sprintf("probe returned HTTP %d", resp.StatusCode)
			serverErrorLatency = latency
			continue
		}

		health := DiagHealth{Status: "online", LatencyMs: latency}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			var info map[string]interface{}
			if json.Unmarshal(body, &info) == nil {
				if v, ok := info["Version"]; ok {
					health.EmbyVer = fmt.Sprintf("%v", v)
				}
			}
			return health
		}

		if !reachable {
			reachable = true
			reachableLatency = latency
		}
	}

	if reachable {
		return DiagHealth{Status: "online", LatencyMs: reachableLatency}
	}
	if serverError != "" {
		return DiagHealth{Status: "error", LatencyMs: serverErrorLatency, Error: serverError}
	}
	return DiagHealth{Status: "offline", Error: "health probe failed"}
}

func diagnoseSite(site *Site, pm *ProxyManager) DiagResult {
	result := DiagResult{}
	profile := getUAProfile(site.UAMode)

	result.Health = probeSiteHealth(site.TargetURL)

	// TLS check
	parsed, _ := normalizeTargetURL(site.TargetURL)
	if parsed != nil && parsed.Scheme == "https" {
		result.TLS.Enabled = true
		host := parsed.Hostname()
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", host+":"+port, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			result.TLS.Error = err.Error()
		} else {
			defer conn.Close()
			certs := conn.ConnectionState().PeerCertificates
			if len(certs) > 0 {
				cert := certs[0]
				result.TLS.Valid = time.Now().Before(cert.NotAfter)
				result.TLS.Issuer = tlsIssuerName(cert)
				result.TLS.ExpiresAt = cert.NotAfter.Format("2006-01-02")
				result.TLS.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
			}
		}
	}

	// Headers
	result.Headers = DiagHeaders{
		UAApplied:   true,
		CurrentUA:   profile.UserAgent,
		ClientField: profile.Client,
	}

	// Proxy status
	result.Proxy = DiagProxy{
		Running:    pm.IsRunning(site.ID),
		ListenPort: site.ListenPort,
	}

	return result
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// HTTP API
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
type App struct {
	db *DB
	pm *ProxyManager
}

func (a *App) jsonOK(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func (a *App) jsonErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			a.jsonErr(w, 401, "missing bearer token")
			return
		}
		_, _, err := validateToken(strings.TrimPrefix(auth, "Bearer "))
		if err != nil {
			a.jsonErr(w, 401, "token expired or invalid")
			return
		}
		next(w, r)
	}
}

// POST /api/auth/setup
func (a *App) handleSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	if a.db.UserCount() > 0 {
		a.jsonErr(w, 400, "admin user already exists")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Username == "" || len(req.Password) < 6 {
		a.jsonErr(w, 400, "username is required and password must be at least 6 characters")
		return
	}
	id, err := a.db.CreateUser(req.Username, req.Password)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	token, err := generateToken(id, req.Username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.jsonOK(w, map[string]interface{}{"token": token, "username": req.Username})
}

// POST /api/auth/login
func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		a.jsonErr(w, 405, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		a.jsonErr(w, 400, "invalid request")
		return
	}
	id, err := a.db.VerifyUser(req.Username, req.Password)
	if err != nil {
		a.jsonErr(w, 401, err.Error())
		return
	}
	token, err := generateToken(id, req.Username)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.jsonOK(w, map[string]interface{}{"token": token, "username": req.Username})
}

// GET /api/auth/check
func (a *App) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	a.jsonOK(w, map[string]interface{}{"needs_setup": a.db.UserCount() == 0})
}

// GET /api/dashboard
func (a *App) handleDashboard(w http.ResponseWriter, r *http.Request) {
	stats := a.db.DashboardStats()
	stats["running_sites"] = a.pm.GetRunningCount()
	a.jsonOK(w, stats)
}

// GET/POST /api/sites
func (a *App) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		sites, err := a.db.ListSites()
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Add running status
		type SiteWithStatus struct {
			Site
			Running bool `json:"running"`
		}
		result := make([]SiteWithStatus, len(sites))
		for i, s := range sites {
			result[i] = SiteWithStatus{Site: s, Running: a.pm.IsRunning(s.ID)}
		}
		a.jsonOK(w, result)

	case "POST":
		var req struct {
			Name              string `json:"name"`
			ListenPort        int    `json:"listen_port"`
			TargetURL         string `json:"target_url"`
			PlaybackTargetURL string `json:"playback_target_url"`
			UAMode            string `json:"ua_mode"`
			Quota             int64  `json:"traffic_quota"`
			SpeedLimit        int    `json:"speed_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		if req.Name == "" || req.ListenPort == 0 || req.TargetURL == "" {
			a.jsonErr(w, 400, "name, listen_port, and target_url are required")
			return
		}
		if req.UAMode == "" {
			req.UAMode = "infuse"
		}
		site, err := a.db.CreateSite(req.Name, req.ListenPort, req.TargetURL, req.PlaybackTargetURL, req.UAMode, req.Quota, req.SpeedLimit)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		// Auto start
		if site.Enabled {
			if err := a.pm.StartSite(*site); err != nil {
				if deleteErr := a.db.DeleteSite(site.ID); deleteErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start site: %v; rollback create: %v", err, deleteErr))
					return
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		w.WriteHeader(201)
		a.jsonOK(w, site)

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// PUT/DELETE /api/sites/{id}, POST /api/sites/{id}/toggle, GET /api/sites/{id}/diag
func (a *App) handleSiteByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/sites/")
	parts := strings.SplitN(path, "/", 2)
	id, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		a.jsonErr(w, 400, "invalid site id")
		return
	}

	action := ""
	if len(parts) > 1 {
		action = parts[1]
	}

	switch {
	case action == "toggle" && r.Method == "POST":
		newState, err := a.db.ToggleSite(id)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		if newState {
			site, err := a.db.GetSite(id)
			if err != nil {
				if _, revertErr := a.db.ToggleSite(id); revertErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("load site: %v; rollback toggle: %v", err, revertErr))
					return
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
			if err := a.pm.StartSite(*site); err != nil {
				if _, revertErr := a.db.ToggleSite(id); revertErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start site: %v; rollback toggle: %v", err, revertErr))
					return
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		} else {
			a.pm.StopSite(id)
		}
		a.jsonOK(w, map[string]interface{}{"enabled": newState})

	case action == "diag" && r.Method == "GET":
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 404, "site not found")
			return
		}
		result := diagnoseSite(site, a.pm)
		a.jsonOK(w, result)

	case action == "" && r.Method == "PUT":
		oldSite, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 404, "site not found")
			return
		}
		var req struct {
			Name              string  `json:"name"`
			ListenPort        int     `json:"listen_port"`
			TargetURL         string  `json:"target_url"`
			PlaybackTargetURL *string `json:"playback_target_url"`
			UAMode            string  `json:"ua_mode"`
			Quota             int64   `json:"traffic_quota"`
			SpeedLimit        int     `json:"speed_limit"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			a.jsonErr(w, 400, "invalid request")
			return
		}
		playbackTargetURL := oldSite.PlaybackTargetURL
		if req.PlaybackTargetURL != nil {
			playbackTargetURL = *req.PlaybackTargetURL
		}
		if req.UAMode == "" {
			req.UAMode = oldSite.UAMode
		}
		if err := a.db.UpdateSite(id, req.Name, req.ListenPort, req.TargetURL, playbackTargetURL, req.UAMode, req.Quota, req.SpeedLimit); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		site, err := a.db.GetSite(id)
		if err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		if site.Enabled {
			needsPreStop := oldSite.Enabled && oldSite.ListenPort == site.ListenPort
			if needsPreStop {
				a.pm.StopSite(id)
			}
			if err := a.pm.StartSite(*site); err != nil {
				if rollbackErr := a.db.UpdateSite(oldSite.ID, oldSite.Name, oldSite.ListenPort, oldSite.TargetURL, oldSite.PlaybackTargetURL, oldSite.UAMode, oldSite.TrafficQuota, oldSite.SpeedLimit); rollbackErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; rollback update: %v", err, rollbackErr))
					return
				}
				restoredSite, getErr := a.db.GetSite(id)
				if getErr != nil {
					a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; reload rollback site: %v", err, getErr))
					return
				}
				if oldSite.Enabled && !a.pm.IsRunning(id) {
					if restartErr := a.pm.StartSite(*restoredSite); restartErr != nil {
						a.jsonErr(w, 500, fmt.Sprintf("start updated site: %v; restore previous site: %v", err, restartErr))
						return
					}
				}
				a.jsonErr(w, 500, err.Error())
				return
			}
		}
		a.jsonOK(w, site)

	case action == "" && r.Method == "DELETE":
		a.pm.StopSite(id)
		if err := a.db.DeleteSite(id); err != nil {
			a.jsonErr(w, 500, err.Error())
			return
		}
		a.jsonOK(w, map[string]string{"status": "deleted"})

	default:
		a.jsonErr(w, 405, "method not allowed")
	}
}

// GET /api/traffic/{site_id}
func (a *App) handleTraffic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/traffic/")

	if path == "overview" {
		stats := a.db.DashboardStats()
		a.jsonOK(w, stats)
		return
	}

	siteID, err := strconv.ParseInt(path, 10, 64)
	if err != nil {
		a.jsonErr(w, 400, "invalid site id")
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil {
			hours = v
		}
	}

	logs, err := a.db.GetTrafficLogs(siteID, hours)
	if err != nil {
		a.jsonErr(w, 500, err.Error())
		return
	}
	a.jsonOK(w, logs)
}

// GET /api/ua-profiles
func (a *App) handleUAProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := make([]UAProfile, 0, len(uaProfiles))
	for _, p := range uaProfiles {
		profiles = append(profiles, p)
	}
	a.jsonOK(w, profiles)
}

// GET /api/events 闂?Server-Sent Events stream
func (a *App) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		a.jsonErr(w, 500, "SSE not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	flusher.Flush()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()

	// Send initial data immediately
	a.sendSSEEvent(w, flusher)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.sendSSEEvent(w, flusher)
		}
	}
}

func (a *App) sendSSEEvent(w http.ResponseWriter, flusher http.Flusher) {
	stats := a.db.DashboardStats()
	stats["running_sites"] = a.pm.GetRunningCount()
	stats["total_requests"] = a.pm.GetTotalRequests()
	stats["uptime_seconds"] = int(time.Since(startTime).Seconds())

	// Collect per-site live stats
	a.pm.mu.RLock()
	siteStats := make([]map[string]interface{}, 0)
	for _, inst := range a.pm.proxies {
		siteStats = append(siteStats, map[string]interface{}{
			"id":        inst.Site.ID,
			"name":      inst.Site.Name,
			"bytes_in":  inst.bytesIn.Load(),
			"bytes_out": inst.bytesOut.Load(),
			"requests":  inst.reqCount.Load(),
			"running":   true,
		})
	}
	a.pm.mu.RUnlock()
	stats["live_sites"] = siteStats

	data, _ := json.Marshal(stats)
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?// Main 闂?with graceful shutdown
// 闂傚倸鍊搁崐椋庣矆娴ｅ搫顥氭い鎾卞灩绾惧潡鏌曢崼婵愭Ц缂佲偓婢舵劗鍙撻柛銉ｅ妿閳藉鏌ｉ妶澶岀暫闁哄矉绱曟禒锔炬嫚閹绘帒顫撻梻浣虹帛閹稿鎯勯鐐茶摕闁绘柨鍚嬮崵瀣亜閹哄棗浜炬繝寰枫倕袚缂佺粯鐩畷銊╊敊閸撗呭帨闂備礁鎼懟顖滅矓瑜版帒绠栨繝濠傚悩閻旂厧浼犻柛鏇炵仛缂嶅倿姊婚崒娆戭槮闁圭⒈鍋婇獮濠呯疀濞戞瑥浜楅梺璺ㄥ枔婵挳寮伴妷鈺傜叆闁绘柨鎼瓭缂備胶濮甸惄顖炲蓟閺囩喓绡€闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及閵夆晜鐓ラ柣鏂挎惈瀛濈紓浣哄У閻╊垶寮婚弴鐔虹瘈闊洦绋掗宥夋⒑缂佹绠栧┑鐐诧工椤繘宕崟顓熸闂佹悶鍎滈崘顭戠€遍梻鍌欑閹诧繝寮婚妸褎宕叉俊顖欒閸ゆ洟鏌＄仦璇插姎闁藉啰鍠栭弻鏇熷緞閸繂濮㈤梺鍛娚戦幃鍌氼潖閾忚鍏滈柛娑卞幘閸旂兘姊洪崨濠冪叆缂佸鎸抽崺銏狀吋閸滀胶鍙嗛梺鍓插亞閸犳捇宕㈤幘缁樷拺缂備焦锚閻忥箓鏌ㄥ顑芥斀妞ゆ梻鎳撴禍楣冩⒒閸屾瑧顦﹂柟纰卞亰楠炲﹨绠涘☉娆忎簵闂佽法鍠撴慨鎾及?
var startTime = time.Now()

func main() {
	port := 9090
	dbPath := "meridian.db"
	if jwtSecretEphemeral {
		log.Printf("JWT_SECRET not set; generated an ephemeral signing secret for this process. Set JWT_SECRET explicitly for stable sessions.")
	}

	if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			port = p
		}
	}
	if v := os.Getenv("DB_PATH"); v != "" {
		dbPath = v
	}

	// Command line args
	for i, arg := range os.Args[1:] {
		switch arg {
		case "--port", "-p":
			if i+1 < len(os.Args)-1 {
				if p, err := strconv.Atoi(os.Args[i+2]); err == nil {
					port = p
				}
			}
		case "--db":
			if i+1 < len(os.Args)-1 {
				dbPath = os.Args[i+2]
			}
		}
	}

	db, err := openDB(dbPath)
	if err != nil {
		log.Fatalf("闂傚倸鍊搁崐宄懊归崶褜娴栭柕濞炬櫆閸ゅ嫰鏌ょ粙璺ㄤ粵婵炲懐濮垫穱濠囧Χ閸屾矮澹曢梻浣风串缁蹭粙鎮樺璺虹闁告侗鍨遍崰鍡涙煕閺囥劌浜滃┑鈩冨▕濮婄粯鎷呯粵瀣秷闂佺瀛╂繛濠傜暦椤栫偛閿ゆ俊銈勭閳ь剙鐖奸弻鏇熷緞閸繂濮夐梺琛″亾闁兼亽鍎禍婊堟煛閸愩劌鈧敻骞忛敓鐘崇厱閹艰揪绱曠粻濠氭煙椤旂瓔娈滄俊顐㈠暙閳藉螣婵傚摜宕滈梺璇查閻忔艾顭垮Ο灏栧亾濮樼厧骞栨い顓炴穿缁犳稑鈽夋潏銊︽珖闂? %v", err)
	}
	defer db.Close()

	pm := NewProxyManager(db)
	pm.StartAllEnabled()

	// Traffic flush goroutine with context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				pm.FlushTraffic()
			case <-ctx.Done():
				return
			}
		}
	}()

	app := &App{db: db, pm: pm}

	mux := http.NewServeMux()

	// CORS middleware wrapper
	cors := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")
			if r.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}
			h(w, r)
		}
	}

	// Public auth routes
	mux.HandleFunc("/api/auth/setup", cors(app.handleSetup))
	mux.HandleFunc("/api/auth/login", cors(app.handleLogin))
	mux.HandleFunc("/api/auth/check", cors(app.handleAuthCheck))

	// Protected routes
	mux.HandleFunc("/api/dashboard", cors(app.authMiddleware(app.handleDashboard)))
	mux.HandleFunc("/api/sites", cors(app.authMiddleware(app.handleSites)))
	mux.HandleFunc("/api/sites/", cors(app.authMiddleware(app.handleSiteByID)))
	mux.HandleFunc("/api/traffic/", cors(app.authMiddleware(app.handleTraffic)))
	mux.HandleFunc("/api/ua-profiles", cors(app.authMiddleware(app.handleUAProfiles)))
	mux.HandleFunc("/api/events", cors(app.authMiddleware(app.handleSSE)))

	// Embedded static files
	staticFS, err := fs.Sub(web.StaticFiles, "static")
	if err != nil {
		log.Fatalf("闂傚倷娴囬褍顫濋敃鍌︾稏濠㈣埖鍔曠粻浼存煙闂傚鍔嶉柛銈嗗姈閵囧嫰寮介顫捕闂佹椿鍘介〃濠囧蓟濞戙垹鐒洪柛鎰典簴濡插牆鈹戦埥鍡椾簼闁挎洏鍨藉璇测槈閵忕姈銊︺亜閺嶎偄浠︽い搴＄Т椤啴濡堕崱妤€顫堢紓渚囧枟閻熲晛顕ｇ拠娴嬫闁靛繒濮烽惈鍕⒑缁嬫寧婀版い鏇熸尦椤㈡鎷呴搹璇″晭闂備礁鎼ˇ浼村垂閼搁潧绶為柛鏇ㄥ幐閸嬫捇宕归锝囧嚒闁诲孩鍑归崢濂糕€﹂崶顏嗙杸婵炴垼椴搁弲婵嬫⒑? %v", err)
	}
	fileServer := http.FileServer(http.FS(staticFS))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		f, err := staticFS.Open(strings.TrimPrefix(path, "/"))
		if err == nil {
			f.Close()
			fileServer.ServeHTTP(w, r)
			return
		}
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})

	// HTTP server with graceful shutdown
	addr := fmt.Sprintf(":%d", port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // no write timeout for streaming
		IdleTimeout:  120 * time.Second,
	}

	log.Println("============================================================")
	log.Println("  Meridian - Emby reverse proxy management panel v1.1")
	log.Printf("  Listening on: http://0.0.0.0%s", addr)
	log.Printf("  Sites loaded: %d (%d running)", func() int { s, _ := db.ListSites(); return len(s) }(), pm.GetRunningCount())
	log.Println("  Features: WebSocket proxy, TLS diagnostics, traffic limits")
	log.Println("============================================================")

	// Signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-sigCh
	log.Println("\nReceived shutdown signal, stopping Meridian...")

	// Cancel background goroutines
	cancel()

	// Shutdown proxies (flushes traffic)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer shutdownCancel()

	pm.GracefulShutdown(shutdownCtx)
	srv.Shutdown(shutdownCtx)

	log.Println("Meridian stopped cleanly")
}
