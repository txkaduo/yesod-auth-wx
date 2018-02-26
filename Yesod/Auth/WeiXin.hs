{-# LANGUAGE ScopedTypeVariables #-}
module Yesod.Auth.WeiXin
  ( wxAuthPluginName
  , wxAuthDummyPluginName
  , YesodAuthWeiXin(..)
  , authWeixin
  , authWeixinDummy
  , module Yesod.Auth.WeiXin.Class
  ) where

-- {{{1
import           ClassyPrelude.Yesod
import           Control.Monad.Except
import           Control.Monad.Trans.Maybe
import           Data.Aeson.Text as A
import           Data.Time.Clock.POSIX
import           Yesod.Auth
import qualified Yesod.Auth.Message          as Msg
import           Yesod.Core.Types            (HandlerContents (HCError))
import           Yesod.WebSockets as WS

import WeiXin.PublicPlatform

import Yesod.Auth.WeiXin.Class
import Yesod.Auth.WeiXin.Utils
-- }}}1


wxAuthPluginName :: Text
wxAuthPluginName = "weixin"

wxAuthDummyPluginName :: Text
wxAuthDummyPluginName = "weixin-dummy"

loginCallbackInR :: AuthRoute
loginCallbackInR = PluginR wxAuthPluginName ["wxcb", "in"]

loginCallbackOutR :: AuthRoute
loginCallbackOutR = PluginR wxAuthPluginName ["wxcb", "out"]

loginQrCodeStartR :: AuthRoute
loginQrCodeStartR = PluginR wxAuthPluginName ["qrcode", "start"]

loginQrCodeScannedR :: Text -> AuthRoute
loginQrCodeScannedR sess = PluginR wxAuthPluginName ["qrcode", "scanned", sess]

loginQrCodeQueryR :: Text -> AuthRoute
loginQrCodeQueryR sess = PluginR wxAuthPluginName ["qrcode", "query", sess]

loginQrCodeDoneR :: Text -> AuthRoute
loginQrCodeDoneR sess = PluginR wxAuthPluginName ["qrcode", "done", sess]

loginQrCodeConfirmR :: Text -> AuthRoute
loginQrCodeConfirmR sess = PluginR wxAuthPluginName ["qrcode", "confirm", sess]

loginQrCodePingR :: Text -> AuthRoute
loginQrCodePingR sess = PluginR wxAuthPluginName ["qrcode", "ping", sess]

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
    dispatch "GET" ["wxcb", "out" ]             = getLoginCallbackOutR >>= sendResponse
    dispatch "GET" ["wxcb", "in" ]              = getLoginCallbackInR >>= sendResponse
    dispatch "GET" ["qrcode", "start" ]         = fmap toTypedContent getLoginQrScanStartR >>= sendResponse
    dispatch "GET" ["qrcode", "scanned", sess ] = fmap toTypedContent (getLoginQrScanScannedR sess) >>= sendResponse
    dispatch "GET" ["qrcode", "query", sess]    = fmap toTypedContent (getLoginQrCodeQueryR sess) >>= sendResponse
    dispatch "POST" ["qrcode", "confirm", sess] = fmap toTypedContent (postLoginQrCodeConfirmR sess) >>= sendResponse
    dispatch "POST" ["qrcode", "ping", sess]    = fmap toTypedContent (postLoginQrCodePingR sess) >>= sendResponse
    dispatch "GET" ["qrcode", "done", sess ]    = fmap toTypedContent (getLoginQrScanDoneR sess) >>= sendResponse
    dispatch _ _                                = notFound

    loginWidget :: (Route Auth -> Route m) -> WidgetT m IO ()
    loginWidget toMaster = do
      in_wx <- isJust <$> handlerGetWeixinClientVersion
      if in_wx
        then do
          let m_comp_app_id = Nothing
          let scope = oauthScopeMinForUnionID

          (, flip (wxppOAuthRequestAuthInsideWx m_comp_app_id) scope, loginCallbackInR)
              <$> handlerToWidget (fmap fst wxAuthConfigInsideWX)
              >>= login_by_redirect_to_wx
        else do
          m_redirect_dat <- fmap (, wxppOAuthRequestAuthOutsideWx, loginCallbackOutR)
                              <$> handlerToWidget (fmap (fmap fst) wxAuthConfigOutsideWX)

          case m_redirect_dat of
            Just x -> login_by_redirect_to_wx x
            Nothing -> do
              master_site <- getYesod
              let m_storage = wxAuthQrCodeStateStorage master_site

              if isJust m_storage
                 then login_by_qrcode
                 else show_error $ asText "不支持微信外登录，请在微信内打开页面"


      where
        login_by_redirect_to_wx (app_id, mk_url, cb_route) = do
          render_url <- getUrlRender
          callback_url <- handlerToWidget $ wxAuthConfigFixReturnUrl $
                                              UrlText $ render_url (toMaster cb_route)
          state <- wxppOAuthMakeRandomState app_id
          let auth_url = mk_url app_id callback_url state
          [whamlet|
            <div .container>
              <p>
                <a href="#{unUrlText auth_url}">点击这里使用微信身份登录
          |]

        login_by_qrcode = do
          [whamlet|
            <div .container>
              <p>
                <a href="@{toMaster loginQrCodeStartR}">点击这里使用微信身份登录
          |]

        show_error msg = do
          [whamlet|
            <div .container>
              <div .alert .alert-danger>
                <strong>出错了!
                #{msg}
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
  lift wxAuthConfigOutsideWX >>= maybe (permissionDenied "不支持微信外登录") getLoginCallbackReal


getLoginQrScanStartR :: YesodAuthWeiXin master
                     => HandlerT Auth (HandlerT master IO) Html
-- {{{1
getLoginQrScanStartR = do
  neverCache

  master_site <- lift getYesod
  route_to_parent <- getRouteToParent

  (_get_stat, save_stat) <- lift handlerGetQrCodeStateStorage

  {-
  m_req_union_id0 <- lift $ runInputGet $ iopt textField "req_union_id"
  let req_union_id = not . null $ T.strip $ fromMaybe "" m_req_union_id0
  --}
  let req_union_id = True -- 目前的逻辑这是必须的

  sess <- fmap fromString $ randomUrlSafeString 64
  -- 若要调试，则要写死生成的 sess 值，否则yesod每次包装tmpXXXX.js文件名都发生变化
  -- (因为我们julius代码里引用了sess的值，它变了就是内容变，以致生成的临时文件也变化了)
  -- let sess = "aaabbcdfasdfasdfxx"

  let init_stat = WxScanQrCodeSess req_union_id def def def False

  lift $ save_stat sess init_stat

  render_url <- getUrlRender
  let scan_url = render_url $ loginQrCodeScannedR sess
      scan_ttl = wxAuthQrCodeStateTTL master_site

  lift $ defaultLayout $ do
    setTitle "微信扫码登录"
    addScriptRemote $ "https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js"
    addScriptRemote $ "https://cdn.bootcss.com/jquery.qrcode/1.0/jquery.qrcode.min.js"
    toWidget [julius|
      var page_load_time = new Date();
      var repeat_id = null;
      var socket = null;

      function show_msg_dialog(msg) {
        $('#msg_dialog #msg').text(msg);
        $('#msg_dialog').modal({
                                backdrop: 'static',
                                keyboard: false
                               });
      }

      function hide_msg_dialog() {
        $('#msg_dialog').modal('hide');
      }

      function handle_server_respone(res) {
        if (res.scanned) {
          if (res.confirmed) {
             window.location = '@{route_to_parent $ loginQrCodeDoneR sess}';
          } else {
            show_msg_dialog('二维码已扫描，请在微信内确认登录');
            if (!socket || socket.readyState != socket.OPEN) {
              repeat_id = setTimeout(query_if_scanned, 1000);
            }
          }
        } else {
          var now = new Date();
          if (now.valueOf() - page_load_time.valueOf() < 1000 * #{toJSON scan_ttl}) {
            if (!socket || socket.readyState != socket.OPEN) {
              repeat_id = setTimeout(query_if_scanned, 1000);
            }
          } else {
            show_msg_dialog('二维码已超时，请刷新页面');
          }
        }
      }

      function query_if_scanned() {
        $.ajax({
          url: '@{route_to_parent $ loginQrCodeQueryR sess}',
          type: 'GET'
        })
        .done(function(dat) {
              var res = dat;
              handle_server_respone(res);
          })
          .fail(function() {
              if (repeat_id) {
                clearTimeout(repeat_id);
              }
              show_msg_dialog('服务器错误，请刷新并重试');
          })
          ;
      }

      $(function () {
        $('#qrcode').qrcode({
                            width: 256,
                            height: 256,
                            text: #{toJSON scan_url}
                           });

        socket = new WebSocket('@{route_to_parent $ loginQrCodeQueryR sess}'.replace(/^http/, 'ws'));
        if (socket) {
           socket.addEventListener('open', function () {
             socket.addEventListener('message', function (event) {
               var res = JSON.parse(event.data);
               handle_server_respone(res);
             });
             socket.addEventListener('error', function (event) {
               show_msg_dialog('服务器错误: ' + event + '，请刷新并重试');
             });
           });

           socket.addEventListener('close', function () {
             // fallback to ajax
             repeat_id = setTimeout(query_if_scanned, 1000);
           });
        } else {
          // fallback to ajax
          repeat_id = setTimeout(query_if_scanned, 1000);
        }
      });

    |]

    -- 为 qrcode 所在的canvas设置居中
    toWidget [lucius|
      canvas {
          padding: 0;
          margin: auto;
          display: block;
      }
    |]

    [whamlet|
      <div .container>
        <h1>若要登录，请使用微信扫一扫扫描以下二维码
        <div #qrcode .center-block>

      <div #msg_dialog .modal role=dialog>
        <div .modal-dialog>
          <div .modal-content>
            <div .modal-body>
              <h4>
                <span #msg>
    |]
-- }}}1


wxQrCodeLoginQueryWebsocksApp :: YesodAuthWeiXin master
                              => Text -> WebSocketsT (HandlerT Auth (HandlerT master IO)) ()
-- {{{1
wxQrCodeLoginQueryWebsocksApp sess = do
  repeat_get_status Nothing $$ sinkWSText
  where
    -- 暂时使用定时查询的方法取数据检查更新
    repeat_get_status m_old = do
      threadDelay $ 1000 * 1000 * 1
      st <- lift get_status
      when (fromMaybe True $ (/= st) <$> m_old) $ do
        yield $ A.encodeToLazyText st

      repeat_get_status (Just st)

    get_status = do
        (_, sess_dat) <- lift $ lift $ handlerGetQrCodeStateStorageAndSession sess
        let (scanned, confirmed) =
              case (wxScanQrCodeSessOpenId &&& wxScanQrCodeSessConfirmed) sess_dat of
                (Just _, b) -> (True, b)
                (Nothing, _) -> (False, False)

        return $
          object [ "scanned" .= scanned
                 , "confirmed" .= confirmed
                 ]
-- }}}1


getLoginQrCodeQueryR :: YesodAuthWeiXin master
                     => Text -> HandlerT Auth (HandlerT master IO) Value
-- {{{1
getLoginQrCodeQueryR sess = do
  webSockets $ wxQrCodeLoginQueryWebsocksApp sess

  neverCache
  (_, sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess

  let (scanned, confirmed) =
        case (wxScanQrCodeSessOpenId &&& wxScanQrCodeSessConfirmed) sess_dat of
          (Just _, b) -> (True, b)
          (Nothing, _) -> (False, False)

  return $
    object [ "scanned" .= scanned
           , "confirmed" .= confirmed
           ]
-- }}}1


postLoginQrCodeConfirmR :: YesodAuthWeiXin master
                        => Text -> HandlerT Auth (HandlerT master IO) Value
-- {{{1
postLoginQrCodeConfirmR sess = do
  neverCache
  ((_get_stat, save_stat), sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess
  let sess_dat' = sess_dat { wxScanQrCodeSessConfirmed = True }

  lift $ save_stat sess sess_dat'
  return $ object []
-- }}}1


postLoginQrCodePingR :: YesodAuthWeiXin master
                     => Text -> HandlerT Auth (HandlerT master IO) Value
-- {{{1
postLoginQrCodePingR sess = do
  neverCache

  ((_get_stat, save_stat), sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess

  now_int <- liftIO $ fmap round $ getPOSIXTime
  let sess_dat' = sess_dat { wxScanQrCodeSessScanTime = Just now_int }

  lift $ save_stat sess sess_dat'

  return $ object []
-- }}}1


wxQrCodeLoginScannedWebsocksApp :: YesodAuthWeiXin master
                                => Text -> WebSocketsT (HandlerT Auth (HandlerT master IO)) ()
-- {{{1
wxQrCodeLoginScannedWebsocksApp sess = do
  let update_sess_time = do
        ((_get_stat, save_stat), sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess
        now_int <- liftIO $ fmap round $ getPOSIXTime
        let sess_dat' = sess_dat { wxScanQrCodeSessScanTime = Just now_int }

        lift $ save_stat sess sess_dat'

  let handle_msg = awaitForever $ \ (_ :: Text) -> lift $ lift update_sess_time

  sourceWS $$ handle_msg
-- }}}1


-- | 微信内打开的页面. 扫描二维码后显示
getLoginQrScanScannedR :: forall master. YesodAuthWeiXin master
                       => Text -> HandlerT Auth (HandlerT master IO) Html
-- {{{1
getLoginQrScanScannedR sess = do
  webSockets $ wxQrCodeLoginScannedWebsocksApp sess

  neverCache

  is_client_wx <- isJust <$> handlerGetWeixinClientVersion
  unless is_client_wx $ permissionDenied "must in WeiXin"

  ((_get_stat, save_stat), sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess
  (app_id, secret_or_broker) <- lift $ wxAuthConfigInsideWX

  wx_api_env <- lift wxAuthConfigApiEnv
  let scope = if wxScanQrCodeSessReqUnionId sess_dat then AS_SnsApiUserInfo else AS_SnsApiBase
      cache = FakeWxppCache

  let get_atk app_id0 code = do
        runExceptT $ getOAuthAccessTokenBySecretOrBroker wx_api_env secret_or_broker app_id0 code

  route_to_parent <- getRouteToParent
  lift $ yesodComeBackWithWxLogin'
   wx_api_env
   cache
   get_atk
   wxAuthConfigFixReturnUrl
   scope
   app_id
   get_open_id_failed
   $ \ open_id m_union_id _m_sns_uinfo -> do
      case m_union_id of
        Nothing | wxScanQrCodeSessReqUnionId sess_dat -> abort_with_msg "no union_id"
        _ -> return ()

      let sess_dat' = sess_dat { wxScanQrCodeSessOpenId = Just open_id
                               , wxScanQrCodeSessUnionId = m_union_id
                               }

      save_stat sess sess_dat'

      -- 因 window.close 在微信内不能用，要引用微信的 js sdk的方法
      ticket <- wxAuthGetJsTicket app_id
                  >>= maybe
                        (error "程序内部错误，请稍后重试：no JS API Ticket available")
                        return

      wx_jssdk_page_url <- fmap UrlText getCurrentUrl
      js_sdk_config_val <- wxppJsApiConfigJsVal app_id ticket False wx_jssdk_page_url wxppJsApiListAll
      let js_sdk_config_code = wxppJsApiConfigCode wx_jssdk_page_url js_sdk_config_val

      defaultLayout $ do
        addScriptRemote $ unUrlText wxppJsSDKUrl
        addScriptRemote $ "https://cdn.bootcss.com/bootstrap/3.3.7/js/bootstrap.min.js"

        toWidget [julius|
          ^{js_sdk_config_code}
          wx.ready(function () {
            wx.hideAllNonBaseMenuItem();
          });

          var repeat_id = null;
          var socket = null;

          function show_msg_dialog(msg) {
            $('#msg_dialog #msg').text(msg);
            $('#msg_dialog').modal({
                                    backdrop: 'static',
                                    keyboard: false
                                   });
          }

          function setup_ajax_loop() {
            repeat_id = setInterval(
                            function () { $.ajax({url: '@{route_to_parent $ loginQrCodePingR sess}', type: 'POST'});
                                        },
                            1000);
          }

          $(function () {
            $("#confirm_btn").click(function () {
              show_msg_dialog("请稍候.....");
              $.ajax({
                url: '@{route_to_parent $ loginQrCodeConfirmR sess}',
                type: 'POST'
              })
              .done(function () {
                wx.closeWindow();
              })
              .fail(function() {
                  if (repeat_id) {
                    clearTimeout(repeat_id);
                  }
                  show_msg_dialog('服务器错误，请刷新并重试');
              })
            });

            socket = new WebSocket('@{route_to_parent $ loginQrCodeScannedR sess}'.replace(/^http/, 'ws'));
            if (socket) {
              socket.addEventListener('open', function () {
                // do nothing, keep alive by ping from server
              });

              socket.addEventListener('close', function () {
                // fallback to ajax
                setup_ajax_loop();
              });
            } else {
              // fallback to ajax
              setup_ajax_loop();
            }

          });
        |]

        [whamlet|
          <div .container>
            <h2>是否允许使用你的微信帐户登录系统?

            <div .center-block>
              <button type=button .btn .btn-lg .btn-primary #confirm_btn>是的，授权登录
              <button type=button .btn .btn-lg .btn-default onclick="wx.closeWindow();">取消

          <div #msg_dialog .modal role=dialog>
            <div .modal-dialog>
              <div .modal-content>
                <div .modal-body>
                  <h4>
                    <span #msg>
        |]
  where
    abort_with_msg msg = do
      throwM $ userError msg

    get_open_id_failed = abort_with_msg "failed to get open id"
-- }}}1


getLoginQrScanDoneR :: YesodAuthWeiXin master
                    => Text -> HandlerT Auth (HandlerT master IO) TypedContent
-- {{{1
getLoginQrScanDoneR sess = do
  app_id <- lift $ fmap fst $ wxAuthConfigInsideWX
  ((_get_stat, _save_stat), sess_dat) <- lift $ handlerGetQrCodeStateStorageAndSession sess

  let (m_open_id, m_union_id) = (wxScanQrCodeSessOpenId &&& wxScanQrCodeSessUnionId) sess_dat

  open_id <- case m_open_id of
               Just x -> return x
               Nothing -> abort_with_msg "unexpected: open is not set?"

  ident <- case m_union_id of
            Nothing -> do
              m_union_id2 <- lift $ wxAuthLookupUnionIdByOpenId app_id open_id
              case m_union_id2 of
                Just x -> return $ unWxppUnionID x
                Nothing -> do
                  $logErrorS logSource "No Union Id available"
                  throwM $ HCError $ InternalError "微信服务配置错误，请稍后重试"

            Just uid -> return $ unWxppUnionID uid

  sessionMarkWxppUser app_id open_id m_union_id
  lift $ setCredsRedirect (Creds wxAuthPluginName ident [])

  where
    abort_with_msg msg = do
      $logErrorS logSource $ "WX QR code login failed: " <> msg
      throwM $ userError $ unpack msg
-- }}}1


getLoginCallbackReal :: YesodAuthWeiXin master
                     => WxOAuthConfig
                     -> HandlerT Auth (HandlerT master IO) TypedContent
-- {{{1
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
            wx_api_env <- lift wxAuthConfigApiEnv
            err_or_atk_info <- runExceptT $ getOAuthAccessTokenBySecretOrBroker wx_api_env secret_or_broker app_id code
            atk_info <- case err_or_atk_info of
                          Right x -> return x
                          Left err -> do
                            $logErrorS logSource $
                                "wxppOAuthGetAccessToken failed: " <> fromString err
                            throwM $ HCError $ InternalError "微信服务接口错误，请稍后重试"

            let open_id = oauthAtkOpenID atk_info
                scopes  = oauthAtkScopes atk_info
                atk_p = getOAuthAccessTokenPkg (app_id, atk_info)

            let get_union_id1 = MaybeT $ return $ oauthAtkUnionID atk_info
                get_union_id2 = do
                  guard $ any oauthScopeCanGetUserInfo scopes

                  err_or_oauth_user_info <- tryWxppWsResult $ flip runReaderT wx_api_env $ wxppOAuthGetUserInfo' atk_p
                  case err_or_oauth_user_info of
                    Left err -> do $logErrorS wxppLogSource $ "wxppOAuthGetUserInfo' failed: " <> tshow err
                                   mzero

                    Right oauth_user_info -> do
                      MaybeT $ return $ oauthUserInfoUnionID oauth_user_info

            m_union_id <- runMaybeT $ get_union_id1 <|> get_union_id2

            ident <- case m_union_id of
                      Nothing -> do
                        $logErrorS logSource "No Union Id available"
                        throwM $ HCError $ InternalError "微信服务配置错误，请稍后重试"
                      Just uid -> return $ unWxppUnionID uid

            sessionMarkWxppUser app_id open_id m_union_id
            lift $ setCredsRedirect (Creds wxAuthPluginName ident [])

        _ -> do
            permissionDenied "用户拒绝授权"
-- }}}1


postLoginDummyR :: (YesodAuth master, RenderMessage master FormMessage)
                  => HandlerT Auth (HandlerT master IO) TypedContent
postLoginDummyR = do
  union_id0 <- lift $ runInputPost $ do
                              ireq textField "union_id"
  lift $ setCredsRedirect (Creds wxAuthDummyPluginName union_id0 [])


-- vim: set foldmethod=marker:
