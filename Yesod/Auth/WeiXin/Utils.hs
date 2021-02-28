module Yesod.Auth.WeiXin.Utils where

import           ClassyPrelude
import           Yesod
import           Control.Monad.Except hiding (replicateM)
import           Data.List                  ((!!))
import           Network.Wai                (rawQueryString)
import           System.Random              (randomIO)
import qualified Control.Exception.Safe as ExcSafe

import           Yesod.Compat
import           WeiXin.PublicPlatform

import           Yesod.Auth.WeiXin.Class


logSource :: Text
logSource = "WeixinAuthPlugin"


{-
hWithRedirectUrl :: (MonadHandler m, site ~ HandlerSite m, YesodAuthWeiXin site)
                   => Route site
                   -> [(Text, Text)]
                   -> OAuthScope
                    -- ^ used only when inside WX
                   -> (WxppAppID -> UrlText -> m a)
                   -> m a
hWithRedirectUrl oauth_return_route params0 oauth_scope f = do
  is_client_wx <- isJust <$> handlerGetWeixinClientVersion

  let params = filter ((/= "code") . fst) params0

  url_render <- getUrlRenderParams
  let oauth_retrurn_url   = UrlText $ url_render oauth_return_route params

  oauth_retrurn_url2 <- liftHandlerT $ wxAuthConfigFixReturnUrl oauth_retrurn_url

  let oauth_rdr_and_app_id = do
        if is_client_wx
           then do
             app_id <- fmap fst wxAuthConfigInsideWX
             random_state <- wxppOAuthMakeRandomState app_id

             let m_comp_app_id = Nothing
             let url = wxppOAuthRequestAuthInsideWx
                                     m_comp_app_id
                                     app_id
                                     oauth_scope
                                     oauth_retrurn_url2
                                     random_state
             return (app_id, url)

           else do
             app_id <- fmap fst wxAuthConfigOutsideWX
             random_state <- wxppOAuthMakeRandomState app_id

             let url = wxppOAuthRequestAuthOutsideWx app_id
                                     oauth_retrurn_url2
                                     random_state
             return (app_id, url)


  (app_id, rdr_url) <- liftHandlerT oauth_rdr_and_app_id
  f app_id rdr_url
--}


neverCache :: MonadHandler m => m ()
neverCache = do
  addHeader "Cache-Control" "no-cache, no-store, must-revalidate"
  addHeader "Pragma" "no-cache"
  addHeader "Expires" "0"


getCurrentUrl :: MonadHandler m => m Text
getCurrentUrl = do
    req <- waiRequest
    current_route <- getCurrentRoute >>= maybe (error "getCurrentRoute failed") return
    url_render <- getUrlRender
    return $ url_render current_route <> decodeUtf8 (rawQueryString req)


getOAuthAccessTokenBySecretOrBroker :: (IsString e, WxppApiBroker a
                                       , HasWxppUrlConfig env, HasWxppUrlConfig env, HasWreqSession env
                                       , ExcSafe.MonadCatch m, MonadIO m, MonadLogger m
                                       )
                                    => env
                                    -> Either WxppAppSecret a
                                    -> WxppAppID
                                    -> OAuthCode
                                    -> ExceptT e m (Maybe OAuthAccessTokenResult)
getOAuthAccessTokenBySecretOrBroker wx_api_env secret_or_broker app_id code = do
  case secret_or_broker of
    Left secret -> do
      err_or_atk_info <- lift $ tryWxppWsResult $
                            flip runReaderT wx_api_env $
                              wxppOAuthGetAccessToken app_id secret code
      case err_or_atk_info of
          Left err -> do
            if fmap wxppToErrorCodeX (wxppCallWxError err) == Just (wxppToErrorCode WxppOAuthCodeHasBeenUsed)
               then return Nothing
               else do
                    $logErrorS logSource $
                        "wxppOAuthGetAccessToken failed: " <> tshow err
                    throwError "微信服务接口错误，请稍后重试"

          Right x -> return $ Just x

    Right broker -> do
      bres <- liftIO $ wxppApiBrokerOAuthGetAccessToken broker app_id code
      case bres of
        Nothing -> do
          $logErrorS logSource $
              "wxppApiBrokerOAuthGetAccessToken return Nothing"
          throwError "程序配置错误，请稍后重试"

        Just (WxppWsResp (Left err@(WxppAppError wxerr _msg))) -> do
          if wxppToErrorCodeX wxerr == wxppToErrorCode WxppOAuthCodeHasBeenUsed
             then return Nothing
             else do
                  $logErrorS logSource $
                      "wxppApiBrokerOAuthGetAccessToken failed: " <> tshow err
                  throwError "微信服务接口错误，请稍后重试"

        Just (WxppWsResp (Right x)) -> return $ Just x


handlerGetQrCodeStateStorage :: (MonadHandler m, HandlerSite m ~ site, YesodAuthWeiXin site)
                             => m ( Text -> HandlerOf site (Maybe WxScanQrCodeSess)
                                  , Text -> WxScanQrCodeSess -> HandlerOf site ()
                                  )
handlerGetQrCodeStateStorage = do
  master_site <- getYesod
  let m_storage = wxAuthQrCodeStateStorage master_site

  case m_storage of
    Just x -> return x
    Nothing -> permissionDenied "no session storage available"



handlerGetQrCodeStateStorageAndSession :: ( m ~ HandlerOf site, YesodAuthWeiXin site)
                                       => Text
                                       -> m ( ( Text -> HandlerOf site (Maybe WxScanQrCodeSess)
                                              , Text -> WxScanQrCodeSess -> HandlerOf site ()
                                              )
                                            , WxScanQrCodeSess
                                            )
handlerGetQrCodeStateStorageAndSession sess = do
  (get_stat, save_stat) <- handlerGetQrCodeStateStorage

  m_sess_dat <- get_stat sess

  sess_dat <- case m_sess_dat of
                Just x -> return x
                Nothing -> permissionDenied "invalid session"

  return ((get_stat, save_stat), sess_dat)


randomPick :: MonadIO m => [a] -> m a
randomPick choices = do
    idx' <- liftIO randomIO
    let idx = abs idx' `rem` chlen
    return $ choices !! idx
    where
        chlen = length choices


randomString :: MonadIO m => Int -> [Char] -> m [Char]
randomString len chars = replicateM len (randomPick chars)


randomUrlSafeString :: MonadIO m => Int -> m [Char]
randomUrlSafeString = flip randomString $ ['0'..'9'] <> ['a'..'z'] <> ['A'..'Z'] <> "-_"
