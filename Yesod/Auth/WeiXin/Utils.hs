module Yesod.Auth.WeiXin.Utils
  ( hGetWxUidFromSession
  , hWithRedirectUrl
  , module Yesod.Auth.WeiXin.Class
  ) where

import           ClassyPrelude.Yesod
import           Control.Monad.Trans.Maybe

import           WeiXin.PublicPlatform

import           Yesod.Auth.WeiXin.Class


hGetWxUidFromSession :: MonadHandler m => WxppAppID -> m (Maybe (WxppAppOpenID, Maybe WxppUnionID))
hGetWxUidFromSession app_id = runMaybeT $ do
  open_id <- MaybeT $ sessionGetWxppUser app_id
  m_union_id <- lift $ fmap WxppUnionID <$> lookupSession sessionKeyWxppUnionId
  return (WxppAppOpenID app_id open_id, m_union_id)


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

             let url = wxppOAuthRequestAuthInsideWx app_id
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
