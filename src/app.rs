use crate::error_template::{AppError, ErrorTemplate};
use leptos::*;
use leptos_meta::*;
use leptos_router::*;

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
            view! { cx, <ErrorTemplate outside_errors/> }
                .into_view(cx)
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
    //use dotenvy_macro::dotenv;

    use oauth2::basic::BasicClient;
    use oauth2::{
        AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
    };

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
    //use dotenvy_macro::dotenv;
    use oauth2::PkceCodeChallenge;
    use oauth2::{CsrfToken, Scope};
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let scopes = dotenvy::var("OAUTH2_SCOPES").unwrap();

    let client = get_client()?;
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes.split(" ").map(|scope| Scope::new(scope.into())))
        //.add_scope(Scope::new("profile".into()))
        //.add_scope(Scope::new("openid".into()))
        //.set_pkce_challenge(pkce_challenge)
        .url();

    _ = pkce_verifier
        .ser()
        .map(|verifier| std::fs::write("verifier.txt", verifier))
        .map_err(|e| ServerFnError::ServerError(e.to_string()))?;
    Ok(auth_url.to_string())
}

/// Renders the home page of your application.
#[component]
fn HomePage(cx: Scope) -> impl IntoView {
    // Creates a reactive value to update the button
    let (count, set_count) = create_signal(cx, 0);
    let on_click = move |_| set_count.update(|count| *count += 1);
    let auth_url_resource = create_resource(cx, || (), move |_| get_oauth2_url(cx));

    view! { cx,
        <h1>"Welcome to Leptos!"</h1>
        <button on:click=on_click>"Click Me: " {count}</button>
        <Suspense fallback=move || {
            view! { cx, <div>"Loading..."</div> }
        }>
            {move || match auth_url_resource.read(cx) {
                None => {
                    view! { cx, <div>"Loading..."</div> }
                        .into_view(cx)
                }
                Some(Err(e)) => {
                    view! { cx, <div>{e.to_string()}</div> }
                        .into_view(cx)
                }
                Some(Ok(auth_url)) => {
                    view! { cx, <a href=auth_url>"Start Login"</a> }
                        .into_view(cx)
                }
            }}
        </Suspense>
    }
}

#[server(TokenRequest, "/api")]
pub async fn token_request(cx: Scope, code: String) -> Result<String, ServerFnError> {
    use oauth2::reqwest::async_http_client;
    use oauth2::AuthType;
    use oauth2::{AuthorizationCode, PkceCodeVerifier};

    let verifier =
        std::fs::read_to_string("verifier.txt").map_err(|e| to_server_fn_error(e.into()))?;
    //let verifier = verifier.replace("\"", "");
    log!("Verifier: {}", verifier);
    let verifier = PkceCodeVerifier::de(verifier.as_str())
        .map_err(|e| ServerFnError::ServerError(e.to_string()))?;
    let client = get_client()?;
    log!("Logging in using {}", code);
    match client
        .set_auth_type(AuthType::RequestBody)
        .exchange_code(AuthorizationCode::new(code))
        //.set_pkce_verifier(verifier)
        .request_async(async_http_client)
        .await
    {
        Err(e) => error!("TokenResponse Error: {:#?}", e),
        Ok(token_result) => log!("Token Response: {:#?}", token_result),
    };
    Ok("working".into())
}

#[component]
fn AuthCallback(cx: Scope) -> impl IntoView {
    let query = move || use_query_map(cx).get();
    let code = query().get("code").unwrap().to_owned();
    let token_request_action = create_server_action::<TokenRequest>(cx);
    token_request_action.dispatch(TokenRequest { code });
    view! { cx, <h1>"Auth Callback"</h1> }
}
