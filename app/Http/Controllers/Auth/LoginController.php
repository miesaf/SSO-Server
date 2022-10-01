<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Providers\RouteServiceProvider;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Laravel\Passport\TokenRepository;
use Laravel\Passport\RefreshTokenRepository;
use Laravel\Passport\Bridge\AuthCodeRepository;
use Laravel\Passport\Passport;

class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function logout(Request $request)
    {
        $tokenRepository = app(TokenRepository::class);
        $refreshTokenRepository = app(RefreshTokenRepository::class);
        $authCodeRepository = app(AuthCodeRepository::class);

        $accessTokens = Passport::token()->where('user_id', auth()->user()->id)->where('revoked', false)->get();

        if($accessTokens->count() > 0) {
            foreach($accessTokens as $accessToken) {
                $tokenRepository->revokeAccessToken($accessToken->id);
                $refreshTokenRepository->revokeRefreshTokensByAccessTokenId($accessToken->id);
            }
        }

        $authCodes = Passport::authCode()->where('user_id', auth()->user()->id)->where('revoked', false)->get();

        if($authCodes->count() > 0) {
            foreach($authCodes as $authCode) {
                $authCodeRepository->revokeAuthCode($authCode->id);
            }
        }

        $this->guard()->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        if ($response = $this->loggedOut($request)) {
            return $response;
        }

        return $request->wantsJson()
            ? new JsonResponse([], 204)
            : redirect('/');
    }
}
