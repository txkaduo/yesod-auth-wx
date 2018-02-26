module Yesod.Auth.WeiXin.Class where

import           ClassyPrelude.Yesod
import           Data.Aeson.TH                 (deriveJSON, fieldLabelModifier, defaultOptions)
import           Data.Aeson.Types              (camelTo2)
import           WeiXin.PublicPlatform
import           Yesod.Auth             (YesodAuth)


type WxOAuthConfig = (WxppAppID, Either WxppAppSecret SomeWxppApiBroker)

data WxScanQrCodeSess =
  WxScanQrCodeSess
    { wxScanQrCodeSessReqUnionId :: Bool
    , wxScanQrCodeSessScanTime   :: Maybe Int64
    -- ^ 用户扫描之后打开的页面会不停更新这个时间
    , wxScanQrCodeSessOpenId     :: Maybe WxppOpenID
    -- ^ 最新的扫描打开的open id
    , wxScanQrCodeSessUnionId    :: Maybe WxppUnionID
    , wxScanQrCodeSessConfirmed  :: Bool
    -- ^ WxScanQrCodeConfirmR 设置为True
    }

$(deriveJSON (defaultOptions { fieldLabelModifier = camelTo2 '_' . drop 15 }) ''WxScanQrCodeSess)

class (YesodAuth site) => YesodAuthWeiXin site where

  -- | The config for OAuth wthin WeiXin client
  -- 用于微信客户端内打开网页时的认证
  wxAuthConfigInsideWX :: HandlerT site IO WxOAuthConfig

  -- | The config for OAuth outside WeiXin client
  -- 用于普通浏览器内打开网页时的认证
  -- Nothing: 代表没相关的app id，若wxAuthQrCodeStateStorage也不能提供相关入口
  -- 则不能使用微信外登录
  wxAuthConfigOutsideWX :: HandlerT site IO (Maybe WxOAuthConfig)
  wxAuthConfigOutsideWX = return Nothing

  -- | 自己实现微信外的扫码登录
  -- 须时值取状态及保存状态的一对函数. Text 参数是一个很长的随机字串
  -- CAUTION: 使用者还需自行保证已保存的状态定期会被消除. 例如使用 Redis 的 expire
  wxAuthQrCodeStateStorage :: site
                           -> Maybe ( Text -> HandlerT site IO (Maybe WxScanQrCodeSess)
                                    , Text -> WxScanQrCodeSess -> HandlerT site IO ()
                                    )
  wxAuthQrCodeStateStorage = const Nothing

  -- | 每个扫描只能在指定时间内完成（秒数）
  wxAuthQrCodeStateTTL :: site -> Int
  wxAuthQrCodeStateTTL = const 600

  -- | 由于微信限制了oauth重定向的返回地址只能用一个固定的域名
  -- 实用时,有多个域名的情况下,通常要做一个固定域名服务器中转一下
  -- 这个方法负责从原始应该使用的地址转换成另一个中转地址
  wxAuthConfigFixReturnUrl :: UrlText -> HandlerT site IO UrlText
  wxAuthConfigFixReturnUrl = return

  wxAuthConfigApiEnv :: HandlerT site IO WxppApiEnv

  wxAuthGetJsTicket :: WxppAppID
                    -> HandlerT site IO (Maybe WxppJsTicket)

  wxAuthLookupUnionIdByOpenId :: WxppAppID
                              -> WxppOpenID
                              -> HandlerT site IO (Maybe WxppUnionID)
