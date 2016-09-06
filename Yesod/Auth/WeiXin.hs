{-# LANGUAGE ScopedTypeVariables #-}
module Yesod.Auth.WeiXin
  ( wxAuthPluginName
  , wxAuthDummyPluginName
  , YesodAuthWeiXin(..)
  , authWeixin
  , authWeixinDummy
  , module Yesod.Auth.WeiXin.Class
  ) where

import           ClassyPrelude.Yesod
import           Yesod.Auth
import qualified Yesod.Auth.Message          as Msg
import           Yesod.Core.Types            (HandlerContents (HCError))

import WeiXin.PublicPlatform

import Yesod.Auth.WeiXin.Class


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


-- | 使用微信 union id 机制作为身份认证
-- 为同时支持微信内、外访问网页，网站必须设置使用 union id，
-- 而不仅是 open id
-- 最后生成的 Creds 中的 ident 部分就是一个 union id
authWeixin :: forall m. YesodAuthWeiXin m => AuthPlugin m
authWeixin =
  AuthPlugin wxAuthPluginName dispatch loginWidget
  where
    dispatch "GET" ["wxcb", "out" ]  = getLoginCallbackOutR >>= sendResponse
    dispatch "GET" ["wxcb", "in" ]   = getLoginCallbackInR >>= sendResponse
    dispatch _ _ = notFound

    loginWidget :: (Route Auth -> Route m) -> WidgetT m IO ()
    loginWidget toMaster = do
      in_wx <- isJust <$> handlerGetWeixinClientVersion
      (app_id, mk_url, cb_route) <-
            if in_wx
              then do
                let m_comp_app_id = Nothing
                let scope = AS_SnsApiUserInfo

                (, flip (wxppOAuthRequestAuthInsideWx m_comp_app_id) scope, loginCallbackInR)
                    <$> handlerToWidget (fmap fst wxAuthConfigInsideWX)
              else do
                (, wxppOAuthRequestAuthOutsideWx, loginCallbackOutR)
                    <$> handlerToWidget (fmap fst wxAuthConfigOutsideWX)
      render_url <- getUrlRender
      callback_url <- handlerToWidget $ wxAuthConfigFixReturnUrl $
                                          UrlText $ render_url (toMaster cb_route)
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
                    => WxOAuthConfig
                    -> HandlerT Auth (HandlerT master IO) TypedContent
getLoginCallbackReal (app_id, secret_or_broker) = do
    m_code <- fmap OAuthCode <$> lookupGetParam "code"

    oauth_state <- liftM (fromMaybe "") $ lookupGetParam "state"
    m_expected_state <- lookupSession (sessionKeyWxppOAuthState app_id)
    unless (m_expected_state == Just oauth_state) $ do
        $logErrorS logSource $
            "OAuth state check failed, got: " <> oauth_state
        permissionDenied "Invalid State"

    case m_code of
        Just code | not (deniedOAuthCode code) -> do
            -- 用户同意授权
            atk_info <- case secret_or_broker of
                          Left secret -> do
                            wx_api_env <- lift wxAuthConfigApiEnv
                            err_or_atk_info <- tryWxppWsResult $
                                                  flip runReaderT wx_api_env $
                                                    wxppOAuthGetAccessToken app_id secret code
                            case err_or_atk_info of
                                Left err -> do
                                    $logErrorS logSource $
                                        "wxppOAuthGetAccessToken failed: " <> tshow err
                                    throwM $ HCError $ InternalError "微信服务接口错误，请稍后重试"

                                Right x -> return x

                          Right broker -> do
                            bres <- liftIO $ wxppApiBrokerOAuthGetAccessToken broker app_id code
                            case bres of
                              Nothing -> do
                                $logErrorS logSource $
                                    "wxppApiBrokerOAuthGetAccessToken return Nothing"
                                throwM $ HCError $ InternalError "程序配置错误，请稍后重试"

                              Just (WxppWsResp (Left err)) -> do
                                $logErrorS logSource $
                                    "wxppApiBrokerOAuthGetAccessToken failed: " <> tshow err
                                throwM $ HCError $ InternalError "微信服务接口错误，请稍后重试"

                              Just (WxppWsResp (Right x)) -> return x

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
