import Foundation

struct XunleiWebTokens {
    var accessToken: String
    var refreshToken: String
    var deviceId: String
    var captchaToken: String
    var userId: String
    var nickname: String
}

struct XunleiStoredAccount: Codable {
    var refreshToken: String
    var deviceId: String
    var captchaToken: String
    var userId: String
    var nickname: String
    var authType: String
}

enum XunleiWebCredential {
    static let clientId = "Xqp0kJBXWhwaTpB6"
    static let storageKey = "credentials_Xqp0kJBXWhwaTpB6"
    static let captchaKey = "captcha_Xqp0kJBXWhwaTpB6"
    static let loginURL = "https://pan.xunlei.com/"
    static let authType = "webToken"
    static let refreshURL = "https://xluser-ssl.xunlei.com/v1/auth/token"
    static let desktopSecChUa = "\"Google Chrome\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\""
    static let desktopSecChUaMobile = "?0"
    static let desktopSecChUaPlatform = "\"Windows\""

    static let readScript = """
        (function(){try{
          var prefix='\(storageKey)';
          var sub=localStorage.getItem('current_sub');
          var raw=sub?localStorage.getItem(prefix+'@'+sub):localStorage.getItem(prefix);
          if(!raw)return '';
          var data=JSON.parse(raw);
          if(!data||typeof data!=='object'||Array.isArray(data))return '';
          if(sub&&data.sub&&String(data.sub)!==sub)return '';
          try{
            var c=JSON.parse(localStorage.getItem('\(captchaKey)')||'{}');
            if(c&&c.token&&Date.parse(c.expires_at)>Date.now())data.captcha_token=c.token;
          }catch(e){}
          try{
            var all=document.cookie.split(';');
            for(var i=0;i<all.length;i++){
              var s=all[i].trim();
              if(s.indexOf('deviceid=')!==0)continue;
              var d=decodeURIComponent(s.slice(9));
              data.device_id=(d.indexOf('.')>-1&&d.length>32)?d.split('.')[1].slice(0,32):d;
              break;
            }
          }catch(e){}
          return encodeURIComponent(JSON.stringify(data));
        }catch(e){return ''}})()
        """

    static let renderFixScript = """
        (function(){try{
          var m=document.querySelector('meta[name="viewport"]');
          if(!m){m=document.createElement('meta');m.setAttribute('name','viewport');(document.head||document.documentElement).appendChild(m);}
          m.setAttribute('content','width=520');
          var s=document.getElementById('yunx-render-fix');
          if(!s){s=document.createElement('style');s.id='yunx-render-fix';(document.head||document.documentElement).appendChild(s);}
          s.textContent=[
            'html,body{height:auto !important;overflow:visible !important;}',
            '#__nuxt,#__layout,.wrapper,.login-page{height:auto !important;overflow:visible !important;}',
            '.pan-share-web-content .banner-wrap{display:none !important;}',
            '.pan-share-web-content .login-web{width:100% !important;max-width:100% !important;}',
            '.login-web iframe,iframe{width:400px !important;max-width:100% !important;}'
          ].join('');
          window.dispatchEvent(new Event('resize'));
        }catch(e){}})()
        """

    static func isValidToken(_ value: String) -> Bool {
        guard value.count >= 16, value.count <= 16384,
              value != "null", value != "undefined" else { return false }
        return value.allSatisfy { $0.isLetter || $0.isNumber || "._~+/=-".contains($0) }
    }

    static func parse(_ raw: String) -> XunleiWebTokens? {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return nil }
        if text.hasPrefix("\"") {
            guard let data = text.data(using: .utf8),
                  let unquoted = try? JSONSerialization.jsonObject(with: data) as? String else { return nil }
            text = unquoted.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { return nil }
        }
        if !text.hasPrefix("{") {
            return parseRawToken(text)
        }
        guard let data = text.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return fieldsFrom(unwrapNested(root))
    }

    private static func parseRawToken(_ text: String) -> XunleiWebTokens? {
        var token = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if token.lowercased().hasPrefix("bearer ") {
            token = String(token.dropFirst(7)).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard isValidToken(token) else { return nil }
        return XunleiWebTokens(accessToken: token, refreshToken: "", deviceId: "",
                               captchaToken: "", userId: "", nickname: "")
    }

    private static func fieldsFrom(_ fields: [String: Any]) -> XunleiWebTokens? {
        func pick(_ keys: String...) -> String {
            for key in keys {
                guard let raw = fields[key] else { continue }
                let text: String
                if let s = raw as? String {
                    text = s
                } else if let n = raw as? NSNumber {
                    text = n.stringValue
                } else {
                    continue
                }
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !trimmed.isEmpty,
                      trimmed.rangeOfCharacter(from: .controlCharacters) == nil else { continue }
                return trimmed
            }
            return ""
        }
        let access = pick("access_token", "accessToken")
        let refresh = pick("refresh_token", "refreshToken")
        if !access.isEmpty, !isValidToken(access) { return nil }
        if !refresh.isEmpty, !isValidToken(refresh) { return nil }
        if access.isEmpty, refresh.isEmpty { return nil }
        let captcha = pick("captcha_token", "captchaToken")
        return XunleiWebTokens(
            accessToken: access,
            refreshToken: refresh,
            deviceId: pick("device_id", "deviceId"),
            captchaToken: isValidToken(captcha) ? captcha : "",
            userId: pick("user_id", "userId", "sub"),
            nickname: pick("nick_name", "nickname", "name", "user_name"))
    }

    private static func unwrapNested(_ root: [String: Any]) -> [String: Any] {
        var current = root
        for _ in 0..<2 {
            if current["access_token"] != nil || current["accessToken"] != nil
                || current["refresh_token"] != nil || current["refreshToken"] != nil {
                return current
            }
            guard let nested = (current["credentials"] as? [String: Any])
                    ?? (current["token"] as? [String: Any])
                    ?? (current["data"] as? [String: Any]) else { return current }
            current = nested
        }
        return current
    }
}

enum XunleiAccount {
    static let recordKey = "yunx.xunlei.webAccount"

    static func load() -> XunleiStoredAccount? {
        guard let raw = YXKeychain.get(recordKey),
              let data = raw.data(using: .utf8),
              let account = try? JSONDecoder().decode(XunleiStoredAccount.self, from: data) else { return nil }
        return account
    }

    static func save(_ account: XunleiStoredAccount) {
        guard let data = try? JSONEncoder().encode(account),
              let raw = String(data: data, encoding: .utf8) else { return }
        YXKeychain.set(raw, for: recordKey)
    }

    static func clear() {
        YXKeychain.remove(recordKey)
        CookieStore.shared.removeCookie(for: .xunlei)
    }

    static func accessToken() -> String {
        PanTool.cookie(.xunlei)
    }

    static func jwtSub(_ token: String) -> String {
        let parts = token.split(separator: ".")
        guard parts.count == 3 else { return "" }
        var base64 = String(parts[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        guard let data = Data(base64Encoded: base64),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let sub = obj["sub"] as? String else { return "" }
        return sub
    }

    static func refreshTokens(refreshToken: String, deviceId: String) async -> (access: String, refresh: String)? {
        let body: [String: Any] = [
            "grant_type": "refresh_token",
            "client_id": XunleiWebCredential.clientId,
            "refresh_token": refreshToken
        ]
        do {
            let response = try await PanTool.json(
                url: XunleiWebCredential.refreshURL,
                method: "POST",
                headers: [
                    "Content-Type": "application/json",
                    "X-Device-Id": deviceId,
                    "X-Client-Id": XunleiWebCredential.clientId,
                    "Origin": "https://pan.xunlei.com",
                    "Referer": "https://pan.xunlei.com/",
                    "User-Agent": YXUA.chromeDesktop,
                    "Sec-Ch-Ua": XunleiWebCredential.desktopSecChUa,
                    "Sec-Ch-Ua-Mobile": XunleiWebCredential.desktopSecChUaMobile,
                    "Sec-Ch-Ua-Platform": XunleiWebCredential.desktopSecChUaPlatform
                ],
                body: PanTool.jsonBody(body),
                injectCookies: false,
                allowStatus: [200])
            let access = response.yxString("access_token") ?? response.yxString("accessToken") ?? ""
            let refresh = response.yxString("refresh_token") ?? response.yxString("refreshToken") ?? ""
            guard !access.isEmpty else { return nil }
            return (access, refresh)
        } catch {
            return nil
        }
    }
}
