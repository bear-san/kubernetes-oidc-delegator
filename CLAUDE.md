# このプロジェクトについて
- これは、Kubernetes の ServiceAccount に対して発行された token を外部から検証するため、JWKs を提供するための API です
- 通常、Kubernetes API はローカルでのみ公開されていますが、この API を通して、AWS のような外部 IdP から、Kubernetes の ServiceAccount に対して発行された token を検証することができます

# 前提
- Kubernetes クラスタは、ServiceAccount に対して token を発行するための署名鍵を持っています
- このプロジェクトでは、Cluster API を用いて、上記の鍵が発行されている前提で動作します
  - つまり、指定された namespace に対して `[Cluster Name]-sa` という名前で秘密鍵・公開鍵が生成されている前提です
- この API は、cobra を用いた CLI として実装されます
- また、Kubernetes API へのアクセスについては、controller-runtime を使用します
  - つまり、このアプリケーションは、Kubernetes クラスタ内で Pod として動作することを想定しています
  - Kubernetes クラスタへのアクセスは、Pod の ServiceAccount を用いて行います

# 動作フロー
- `SERVER_HOST/[Project ID]/[Cluster Name]/.well-known/openid-configuration` にアクセスすると、JWKs の URL が返却されます
  - この時、`[Project ID]` は OpenStack のプロジェクト ID であり、クラスタの Namespace ですが、クラスタ管理者によって独自の Prefix/Suffix が付記されることがあるため、このフォーマットについては API サーバー起動時の引数で指定できるようにしてください
- `SERVER_HOST/[Project ID]/[Cluster Name]/keys` にアクセスすると、JWKs が返却されます

## ファイルフォーマット
### OpenID Configuration
```json
{
    "issuer": "https://kubernetes.default.svc.cluster.local",
    "jwks_uri": "https://10.194.230.72:6443/openid/v1/jwks",
    "response_types_supported": [
      "id_token"
    ],
    "subject_types_supported": [
      "public"
    ],
    "id_token_signing_alg_values_supported": [
      "RS256"
    ]
}
```

### JWKs
```json
{
    "keys": [
        {
            "use": "sig",
            "kty": "RSA",
            "kid": "XBRQklg6V4uMi9zGXrC1d_gqrT4tKWKyM6iZzXKiYhQ",
            "alg": "RS256",
            "n": "1jfO8HAAowQhhmrJLKOZPMuKPTZlaruCCTbKURpViqbltcXUwJzdgkgobu5yi3H_I4l9aqCvyjzNnEiP3oux3l6oP49D-5VBoS7PuifP8ZCV6fO8_4O-2h9rbwh1TaGfSIAoJw3CydF4DWAdN4rqyaDL82suX2HOAmDgZs8Lz7eBeQS2ztE9Lhh-YGfsMwIskd_3rvzbFZrY7L_rDYh-W0Zsvt-7twlQwjqoudC7gQMILe6zEP8MB3MmQKhd1ZPeqD8esbMYcwO2409SSxxHg48t_j3Uh1bCS08kFRMOgybk0luLzwx6sqruUUrf9OgEPyZCiFZB8nWlGUC7IqA4aQ",
            "e": "AQAB"
        }
    ]
}
```
