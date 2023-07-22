use crate::error_template::{AppError, ErrorTemplate};
use http::{header, HeaderName, HeaderValue};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;
use reqwest::Url;

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    // Provides context that manages stylesheets, titles, meta tags, etc.
    provide_meta_context(cx);

    view! { cx,
        <Stylesheet id="leptos" href="/pkg/start-axum.css"/>
        <Title text="Welcome to Leptos"/>
        <Router fallback=|cx| {
            let mut outside_errors = Errors::default();
            outside_errors.insert_with_default_key(AppError::NotFound);
            view! { cx, <ErrorTemplate outside_errors/> }.into_view(cx)
        }>
            <main>
                <Routes>
                    <Route
                        path=""
                        view=|cx| {
                            view! { cx, <HomePage/> }
                        }
                    />
                    <Route
                        path="/callback"
                        view=|cx| {
                            view! { cx, <AuthCallback/> }
                        }
                    />
                    <Route
                        path="/profile"
                        view=|cx| {
                            view! { cx, <Profile/> }
                        }
                    />
                </Routes>
            </main>
        </Router>
    }
}

pub fn to_server_fn_error(error: error::Error) -> ServerFnError {
    ServerFnError::ServerError(error.to_string())
}

#[cfg(feature = "ssr")]
pub fn get_client() -> Result<oauth2::basic::BasicClient, ServerFnError> {
    use oauth2::basic::BasicClient;
    use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

    let client = BasicClient::new(
        ClientId::new(dotenvy::var("OAUTH2_CLIENT_ID").unwrap()),
        Some(ClientSecret::new(
            dotenvy::var("OAUTH2_CLIENT_SECRET").unwrap(),
        )),
        AuthUrl::new(dotenvy::var("OAUTH2_AUTH_URI").unwrap())
            .map_err(|pe| to_server_fn_error(pe.into()))?,
        Some(TokenUrl::new(dotenvy::var("OAUTH2_TOKEN_URI").unwrap())?),
    )
    .set_redirect_uri(
        RedirectUrl::new(dotenvy::var("OAUTH2_REDIRECT_URI").unwrap())
            .map_err(|pe| to_server_fn_error(pe.into()))?,
    );
    Ok(client)
}

#[server(GetOAuth2Url, "/api")]
pub async fn get_oauth2_url(cx: Scope) -> Result<String, ServerFnError> {
    use oauth2::{CsrfToken, Scope};
    let scopes = dotenvy::var("OAUTH2_SCOPES").unwrap();

    let client = get_client()?;
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes.split(" ").map(|scope| Scope::new(scope.into())))
        .url();

    Ok(auth_url.to_string())
}

#[server(TokenRequest, "/api")]
pub async fn token_request(cx: Scope, code: String) -> Result<bool, ServerFnError> {
    use axum_extra::extract::cookie::Cookie;
    use axum_extra::extract::cookie::SameSite;
    use leptos_axum::ResponseOptions;
    use oauth2::reqwest::async_http_client;
    use oauth2::AuthorizationCode;
    use oauth2::{AuthType, TokenResponse};

    let client = get_client()?;
    log!("Logging in using {}", code);

    let response = expect_context::<ResponseOptions>(cx);
    match client
        .set_auth_type(AuthType::RequestBody)
        .exchange_code(AuthorizationCode::new(code))
        .request_async(async_http_client)
        .await
    {
        Err(e) => {
            error!("TokenResponse Error: {:#?}", e);
            Ok(false)
        }
        Ok(token_result) => {
            log!("Token Response: {:#?}", token_result);
            let access_token = token_result.access_token().to_owned();
            log!("Access Token: {:#?}", access_token.secret());
            let mut cookie = Cookie::new("access_token", access_token.secret());
            cookie.set_http_only(true);
            cookie.set_same_site(SameSite::Lax);
            let Ok(cookie) = HeaderValue::from_str(&cookie.to_string()) else {
                    return Ok(false);
                };
            log!("Adding cookie");
            response.append_header(header::SET_COOKIE, cookie);
            log!("Cookie added");

            Ok(true)
        }
    }
}
/// Renders the home page of your application.
#[component]
fn HomePage(cx: Scope) -> impl IntoView {
    let auth_url_resource = create_resource(cx, || (), move |_| get_oauth2_url(cx));

    view! { cx,
        <h1>"Welcome to Leptos!"</h1>
        <Suspense fallback=move || {
            view! { cx, <div>"Loading..."</div> }
        }>
            {move || match auth_url_resource.read(cx) {
                None => view! { cx, <div>"Loading..."</div> }.into_view(cx),
                Some(Err(e)) => view! { cx, <div>{e.to_string()}</div> }.into_view(cx),
                Some(Ok(auth_url)) => view! { cx, <a href=auth_url>"Start Login"</a> }.into_view(cx),
            }}
        </Suspense>
    }
}

#[component]
fn AuthCallback(cx: Scope) -> impl IntoView {
    let query = move || use_query_map(cx).get();
    let code = query().get("code").unwrap().to_owned();
    let token_resource =
        create_blocking_resource(cx, || (), move |_| token_request(cx, code.clone()));
    view! { cx,
        <h1>"Auth Callback"</h1>
        <Suspense fallback=|| ()>
            {move || {
                token_resource
                    .with(
                        cx,
                        |token| {
                            let Ok(auth_complete) = token else {
                            return view! { cx, <div>"Nothing"</div> }.into_view(cx);
                        };
                            view! { cx,
                                <div>"Token Received: " {format!("{:?}", auth_complete)}</div>
                            }
                                .into_view(cx)
                        },
                    )
            }}
        </Suspense>
    }
}

#[server(GetProfile, "/api")]
pub async fn get_profile(cx: Scope) -> Result<bool, ServerFnError> {
    use axum_extra::extract::CookieJar;
    use oauth2::reqwest::async_http_client;
    use oauth2::AccessToken;
    use oauth2::{StandardTokenIntrospectionResponse, TokenIntrospectionResponse};
    let response = leptos_axum::extract(cx, |cookies: CookieJar| async move {
        let Some(cookie) = cookies.get("access_token") else {
            return false;
        };
        let token = cookie.value();
        let client = reqwest::Client::default();
        let mut request = reqwest::Request::new(
            http::method::Method::GET,
            Url::parse(dotenvy::var("OAUTH2_USER_INFO_URI").unwrap().as_str()).unwrap(),
        );
        request.headers_mut().append(
            header::AUTHORIZATION,
            HeaderValue::from_str(format!("Bearer {}", token).as_str()).unwrap(),
        );
        log!("UserInfo Request: {:#?}", request);
        let response = client.execute(request).await;
        log!("Checking Access Token: {}", token);
        log!("UserInfo Response: {:#?}", response);
        log!("{:#?}", response.unwrap().text().await);
        let mut request = reqwest::Request::new(
            http::Method::GET,
            Url::parse(dotenvy::var("OAUTH2_INTROSPECTION_URI").unwrap().as_str()).unwrap(),
        );
        request
            .url_mut()
            .set_query(Some(format!("access_token={}", token).as_str()));
        let response = client.execute(request).await;
        log!("TokenInfo Response: {:#?}", response);
        log!("{:#?}", response.unwrap().text().await);
        true
    })
    .await
    .map_err(|e| ServerFnError::ServerError("Unable to extract cookies".into()));
    response
}

#[component]
pub fn Profile(cx: Scope) -> impl IntoView {
    let profile = create_resource(cx, || (), move |_| get_profile(cx));
    profile.read(cx);
    view! { cx, <h1>"Profile"</h1> }
}
