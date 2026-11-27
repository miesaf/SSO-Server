<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\Hash;
use Laravel\Passport\Passport;

/*
 * Passport 13 always hashes client secrets and checks them with Hash::check(); Passport 10
 * stored them in plain text. This does what `php artisan passport:hash --force` does, so
 * existing SSO clients keep logging in with the secret already in their .env. Secrets that
 * are hashed already are left alone, so it is safe to run more than once.
 */
return new class extends Migration
{
    /**
     * Get the migration connection name.
     */
    public function getConnection(): ?string
    {
        return $this->connection ?? config('passport.connection');
    }

    /**
     * Run the migrations.
     */
    public function up(): void
    {
        foreach (Passport::client()->newQuery()->whereNotNull('secret')->cursor() as $client) {
            if (Hash::isHashed($client->secret) && ! Hash::needsRehash($client->secret)) {
                continue;
            }

            $client->timestamps = false;
            $client->forceFill(['secret' => $client->secret])->save();
        }
    }

    /**
     * Reverse the migrations (a hash cannot be turned back into the secret).
     */
    public function down(): void
    {
        //
    }
};
