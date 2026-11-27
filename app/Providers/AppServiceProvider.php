<?php

namespace App\Providers;

use App\Models\Passport\Client;
use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Laravel\Passport\Passport;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        // Passport 13 turns the device code grant on by default; this server only serves the
        // authorization code flow and has no oauth_device_codes table. Set before Passport boots,
        // which is when it registers its routes.
        Passport::$deviceCodeGrantEnabled = false;
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('api', function (Request $request) {
            return Limit::perMinute(60)->by($request->user()?->id ?: $request->ip());
        });

        // Trusted clients skip the consent page (see App\Models\Passport\Client).
        Passport::useClientModel(Client::class);

        // Passport is headless since 13.0: this view asks the user to approve untrusted clients.
        Passport::authorizationView('passport.authorize');

        Passport::tokensExpireIn(now()->addDays(1));
        Passport::refreshTokensExpireIn(now()->addDays(30));
        Passport::personalAccessTokensExpireIn(now()->addMonths(6));
    }
}
