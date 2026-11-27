<?php

namespace App\Models\Passport;

use Illuminate\Contracts\Auth\Authenticatable;
use Laravel\Passport\Client as PassportClient;

class Client extends PassportClient
{
    /**
     * Get the attributes that should be cast.
     *
     * @return array<string, string>
     */
    protected function casts(): array
    {
        return [
            'trusted' => 'bool',
        ];
    }

    /**
     * Trusted clients (oauth_clients.trusted, the default for new clients) are approved
     * without showing the "Authorization Request" page; untrusted ones ask the user once,
     * then Passport approves them while the user holds a valid token for the client.
     */
    public function skipsAuthorization(Authenticatable $user, array $scopes): bool
    {
        return (bool) $this->trusted;
    }
}
