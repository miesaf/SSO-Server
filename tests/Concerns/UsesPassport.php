<?php

namespace Tests\Concerns;

use App\Models\Passport\Client;
use Laravel\Passport\ClientRepository;

trait UsesPassport
{
    /** @var array{private: string, public: string}|null */
    private static ?array $passportKeys = null;

    /**
     * Give Passport a throw-away RSA key pair, so tests never touch storage/oauth-*.key.
     */
    protected function setUpPassportKeys(): void
    {
        if (self::$passportKeys === null) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            openssl_pkey_export($key, $private);

            self::$passportKeys = [
                'private' => $private,
                'public' => openssl_pkey_get_details($key)['key'],
            ];
        }

        config([
            'passport.private_key' => self::$passportKeys['private'],
            'passport.public_key' => self::$passportKeys['public'],
        ]);
    }

    /**
     * Register an SSO client app the way `php artisan passport:client` does.
     */
    protected function makeClient(bool $trusted = true, string $redirect = 'https://client.test/auth/callback'): Client
    {
        $client = app(ClientRepository::class)->createAuthorizationCodeGrantClient('SSO Client', [$redirect]);

        $client->forceFill(['trusted' => $trusted])->save();

        return $client;
    }
}
