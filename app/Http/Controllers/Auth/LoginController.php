<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
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

    use AuthenticatesUsers {
        logout as endSession;
    }

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/home';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('auth')->only('logout');
    }

    /**
     * Log the user out of the SSO server and revoke everything it issued to them,
     * so every client app has to send the user through the login page again.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Http\JsonResponse
     */
    public function logout(Request $request)
    {
        $userId = $request->user()->getAuthIdentifier();

        $accessTokenIds = Passport::token()->newQuery()
            ->where('user_id', $userId)
            ->where('revoked', false)
            ->pluck('id');

        Passport::token()->newQuery()->whereIn('id', $accessTokenIds)->update(['revoked' => true]);
        Passport::refreshToken()->newQuery()->whereIn('access_token_id', $accessTokenIds)->update(['revoked' => true]);
        Passport::authCode()->newQuery()->where('user_id', $userId)->where('revoked', false)->update(['revoked' => true]);

        return $this->endSession($request);
    }
}
