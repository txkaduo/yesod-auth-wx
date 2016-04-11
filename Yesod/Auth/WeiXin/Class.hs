module Yesod.Auth.WeiXin.Class where

import           ClassyPrelude.Yesod
import           WeiXin.PublicPlatform
import           Yesod.Auth             (YesodAuth)


type WxOAuthConfig = (WxppAppID, Either WxppAppSecret SomeWxppApiBroker)

class (YesodAuth site) => YesodAuthWeiXin site where

  -- | The config for OAuth wthin WeiXin client
  -- 用于微信客户端内打开网页时的认证
  wxAuthConfigInsideWX :: HandlerT site IO WxOAuthConfig

  -- | The config for OAuth outside WeiXin client
  -- 用于普通浏览器内打开网页时的认证
  wxAuthConfigOutsideWX :: HandlerT site IO WxOAuthConfig

  -- | 由于微信限制了oauth重定向的返回地址只能用一个固定的域名
  -- 实用时,有多个域名的情况下,通常要做一个固定域名服务器中转一下
  -- 这个方法负责从原始应该使用的地址转换成另一个中转地址
  wxAuthConfigFixReturnUrl :: UrlText -> HandlerT site IO UrlText
  wxAuthConfigFixReturnUrl = return

  wxAuthConfigApiEnv :: HandlerT site IO WxppApiEnv
