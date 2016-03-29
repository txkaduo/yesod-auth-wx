{-# LANGUAGE ScopedTypeVariables #-}
module Yesod.Auth.WeiXin
  ( wxAuthPluginName
  , wxAuthDummyPluginName
  , YesodAuthWeiXin(..)
  , authWeixin
  , authWeixinDummy
  ) where

import           ClassyPrelude.Yesod
import qualified Network.Wreq.Session        as WS
import           Yesod.Auth
import qualified Yesod.Auth.Message          as Msg
import           Yesod.Core.Types            (HandlerContents (HCError))

import WeiXin.PublicPlatform

wxAuthPluginName :: Text
wxAuthPluginName = "weixin"

wxAuthDummyPluginName :: Text
wxAuthDummyPluginName = "weixin-dummy"

loginCallbackInR :: AuthRoute
loginCallbackInR = PluginR wxAuthPluginName ["wxcb", "in"]

loginCallbackOutR :: AuthRoute
loginCallbackOutR = PluginR wxAuthPluginName ["wxcb", "out"]

loginDummyR :: AuthRoute
loginDummyR = PluginR wxAuthDummyPluginName ["login"]


class (YesodAuth site) => YesodAuthWeiXin site where

  -- | The config for OAuth wthin WeiXin client
  -- 用于微信客户端内打开网页时的认证
  wxAuthConfigInsideWX :: HandlerT site IO WxppAuthConfig

  -- | The config for OAuth outside WeiXin client
  -- 用于普通浏览器内打开网页时的认证
  wxAuthConfigOutsideWX :: HandlerT site IO WxppAuthConfig

  -- | 由于微信限制了oauth重定向的返回地址只能用一个固定的域名
  -- 实用时,有多个域名的情况下,通常要做一个固定域名服务器中转一下
  -- 这个方法负责从原始应该使用的地址转换成另一个中转地址
  wxAuthConfigFixReturnUrl :: UrlText -> HandlerT site IO UrlText
  wxAuthConfigFixReturnUrl = return

  wxAuthConfigApiEnv :: HandlerT site IO WxppApiEnv


-- | 使用微信 union id 机制作为身份认证
-- 为同时支持微信内、外访问网页，网站必须设置使用 union id，
-- 而不仅是 open id
-- 最后生成的 Creds 中的 ident 部分就是一个 union id
authWeixin :: forall m. YesodAuthWeiXin m => AuthPlugin m
authWeixin =
  AuthPlugin wxAuthPluginName dispatch loginWidget
  where
    dispatch "POST" ["wxcb", "out" ]  = getLoginCallbackOutR >>= sendResponse
    dispatch "GET" ["wxcb", "in" ]   = getLoginCallbackInR >>= sendResponse
    dispatch _ _ = notFound

    loginWidget :: (Route Auth -> Route m) -> WidgetT m IO ()
    loginWidget toMaster = do
      in_wx <- isJust <$> handlerGetWeixinClientVersion
      (auth_config, mk_url, cb_route) <-
            if in_wx
              then do
                let scope = AS_SnsApiUserInfo
                (, flip wxppOAuthRequestAuthInsideWx scope, loginCallbackInR)
                    <$> handlerToWidget wxAuthConfigInsideWX
              else do
                (, wxppOAuthRequestAuthOutsideWx, loginCallbackOutR)
                    <$> handlerToWidget wxAuthConfigOutsideWX
      render_url <- getUrlRender
      callback_url <- handlerToWidget $ wxAuthConfigFixReturnUrl $
                                          UrlText $ render_url (toMaster cb_route)
      let app_id = wxppAuthAppID auth_config
      state <- wxppOAuthMakeRandomState app_id
      let auth_url = mk_url app_id callback_url state
      [whamlet|
        <p>
          <a href="#{unUrlText auth_url}">点击这里使用微信身份登录
      |]


-- | 为方便测试做的假微信登录
-- 用户可以输入任意字串作为 union id 登录
authWeixinDummy :: (YesodAuth m, RenderMessage m FormMessage) => AuthPlugin m
authWeixinDummy =
  AuthPlugin wxAuthDummyPluginName dispatch loginWidget
  where
    dispatch "POST" ["login"] = postLoginDummyR >>= sendResponse
    dispatch _ _ = notFound

    loginWidget toMaster =
      [whamlet|
        $newline never
        <form method="post" action="@{toMaster loginDummyR}">
          <table>
            <tr>
              <th>Union Id
              <td>
                 <input type="text" name="union_id" required>
            <tr>
              <td colspan="2">
                <button type="submit" .btn .btn-success>_{Msg.LoginTitle}
      |]

getLoginCallbackInR :: YesodAuthWeiXin master
                    => HandlerT Auth (HandlerT master IO) TypedContent
getLoginCallbackInR = do
    lift wxAuthConfigInsideWX >>= getLoginCallbackReal

getLoginCallbackOutR :: YesodAuthWeiXin master
                    => HandlerT Auth (HandlerT master IO) TypedContent
getLoginCallbackOutR = do
    lift wxAuthConfigOutsideWX >>= getLoginCallbackReal

logSource :: Text
logSource = "WeixinAuthPlugin"

getLoginCallbackReal :: YesodAuthWeiXin master
                    => WxppAuthConfig
                    -> HandlerT Auth (HandlerT master IO) TypedContent
getLoginCallbackReal auth_config = do
    m_code <- fmap OAuthCode <$> lookupGetParam "code"
    let app_id = wxppAuthAppID auth_config
        secret = wxppAuthAppSecret auth_config

    oauth_state <- liftM (fromMaybe "") $ lookupGetParam "state"
    m_expected_state <- lookupSession (sessionKeyWxppOAuthState app_id)
    unless (m_expected_state == Just oauth_state) $ do
        $logErrorS logSource $
            "OAuth state check failed, got: " <> oauth_state
        permissionDenied "Invalid State"

    case m_code of
        Just code | not (deniedOAuthCode code) -> do
            -- 用户同意授权
            wx_api_env <- lift wxAuthConfigApiEnv
            err_or_atk_info <- tryWxppWsResult $
                                  flip runReaderT wx_api_env $
                                    wxppOAuthGetAccessToken app_id secret code
            atk_info <- case err_or_atk_info of
                            Left err -> do
                                $logErrorS logSource $
                                    "wxppOAuthGetAccessToken failed: " <> tshow err
                                throwM $ HCError $ InternalError "微信服务接口错误，请稍后重试"

                            Right x -> return x

            let m_union_id = oauthAtkUnionID atk_info

            ident <- case m_union_id of
                      Nothing -> do
                        $logErrorS logSource "No Union Id available"
                        throwM $ HCError $ InternalError "微信服务配置错误，请稍后重试"
                      Just uid -> return $ unWxppUnionID uid

            lift $ setCredsRedirect (Creds wxAuthPluginName ident [])

        _ -> do
            permissionDenied "用户拒绝授权"


postLoginDummyR :: (YesodAuth master, RenderMessage master FormMessage)
                  => HandlerT Auth (HandlerT master IO) TypedContent
postLoginDummyR = do
  union_id0 <- lift $ runInputPost $ do
                              ireq textField "union_id"
  lift $ setCredsRedirect (Creds wxAuthDummyPluginName union_id0 [])
