<?php

namespace Tests\Feature;

use App\Models\Passport\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Illuminate\Testing\TestResponse;
use Laravel\Passport\Passport;
use Tests\Concerns\UsesPassport;
use Tests\TestCase;

/**
 * The authorization code flow miesaf/SSO-Client runs against this server:
 * GET /oauth/authorize → POST /oauth/token → GET /api/user.
 */
class SsoFlowTest extends TestCase
{
    use RefreshDatabase, UsesPassport;

    private const REDIRECT = 'https://client.test/auth/callback';

    protected function setUp(): void
    {
        parent::setUp();

        $this->setUpPassportKeys();
    }

    private function authorizeQuery(Client $client, string $state): string
    {
        return '/oauth/authorize?'.http_build_query([
            'client_id' => $client->getKey(),
            'redirect_uri' => self::REDIRECT,
            'response_type' => 'code',
            'scope' => '',
            'state' => $state,
        ]);
    }

    /**
     * Pull the code out of the redirect back to the client, checking the state on the way.
     */
    private function codeFrom(TestResponse $response, string $state): string
    {
        $response->assertRedirect();

        $location = $response->headers->get('Location');
        $this->assertStringStartsWith(self::REDIRECT.'?', $location);

        parse_str(parse_url($location, PHP_URL_QUERY), $query);
        $this->assertSame($state, $query['state'] ?? null);
        $this->assertNotEmpty($query['code'] ?? null);

        return $query['code'];
    }

    private function exchange(Client $client, string $code, ?string $secret = null): TestResponse
    {
        return $this->post('/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $client->getKey(),
            'client_secret' => $secret ?? $client->plainSecret,
            'redirect_uri' => self::REDIRECT,
            'code' => $code,
        ]);
    }

    private function apiUser(string $accessToken): TestResponse
    {
        // Drop the session user from earlier requests so only the bearer token counts.
        $this->app['auth']->forgetGuards();
        $this->flushSession();

        return $this->withHeaders([
            'Accept' => 'application/json',
            'Authorization' => 'Bearer '.$accessToken,
        ])->get('/api/user');
    }

    public function test_a_guest_is_sent_to_the_login_page_first(): void
    {
        $client = $this->makeClient();

        $this->get($this->authorizeQuery($client, Str::random(40)))->assertRedirect('/login');
    }

    public function test_after_login_the_user_returns_to_the_authorization_request(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();
        $state = Str::random(40);

        $this->get($this->authorizeQuery($client, $state))->assertRedirect('/login');

        $this->post('/login', ['email' => $user->email, 'password' => 'password'])
            ->assertRedirect(url($this->authorizeQuery($client, $state)));

        $this->codeFrom($this->get($this->authorizeQuery($client, $state)), $state);
    }

    public function test_a_trusted_client_gets_a_code_a_token_and_the_user(): void
    {
        $client = $this->makeClient(trusted: true);
        $user = User::factory()->create();
        $state = Str::random(40);

        $code = $this->codeFrom(
            $this->actingAs($user)->get($this->authorizeQuery($client, $state)),
            $state
        );

        $token = $this->exchange($client, $code)
            ->assertOk()
            ->assertJsonStructure(['token_type', 'expires_in', 'access_token', 'refresh_token'])
            ->assertJsonPath('token_type', 'Bearer');

        // Passport::tokensExpireIn(1 day).
        $this->assertEqualsWithDelta(86400, $token->json('expires_in'), 5);

        $this->apiUser($token->json('access_token'))
            ->assertOk()
            ->assertJsonPath('id', $user->id)
            ->assertJsonPath('email', $user->email)
            ->assertJsonPath('name', $user->name)
            ->assertJsonMissingPath('password')
            ->assertJsonMissingPath('remember_token');
    }

    public function test_a_code_works_only_once(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();
        $state = Str::random(40);

        $code = $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $state)), $state);

        $this->exchange($client, $code)->assertOk();
        $this->exchange($client, $code)->assertStatus(400)->assertJsonPath('error', 'invalid_grant');
    }

    public function test_a_wrong_client_secret_is_refused(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();
        $state = Str::random(40);

        $code = $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $state)), $state);

        $this->exchange($client, $code, 'not-the-secret')->assertStatus(401)->assertJsonPath('error', 'invalid_client');
    }

    public function test_an_unknown_redirect_uri_is_refused(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();

        $this->actingAs($user)->get('/oauth/authorize?'.http_build_query([
            'client_id' => $client->getKey(),
            'redirect_uri' => 'https://evil.test/callback',
            'response_type' => 'code',
            'state' => Str::random(40),
        ]))->assertStatus(401);
    }

    public function test_an_untrusted_client_asks_the_user_and_then_issues_a_code(): void
    {
        $client = $this->makeClient(trusted: false);
        $user = User::factory()->create();
        $state = Str::random(40);

        $this->actingAs($user)->get($this->authorizeQuery($client, $state))
            ->assertOk()
            ->assertSee('Authorization Request')
            ->assertSee($client->name)
            ->assertSee(route('passport.authorizations.approve'), false);

        $code = $this->codeFrom($this->post('/oauth/authorize', [
            'state' => $state,
            'client_id' => $client->getKey(),
            'auth_token' => session('authToken'),
        ]), $state);

        $accessToken = $this->exchange($client, $code)->assertOk()->json('access_token');

        $this->apiUser($accessToken)->assertOk()->assertJsonPath('id', $user->id);

        // With a valid token for this client, the next login skips the question.
        $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $next = Str::random(40))), $next);
    }

    public function test_denying_an_untrusted_client_sends_access_denied_back(): void
    {
        $client = $this->makeClient(trusted: false);
        $user = User::factory()->create();
        $state = Str::random(40);

        $this->actingAs($user)->get($this->authorizeQuery($client, $state))->assertOk();

        $response = $this->delete('/oauth/authorize', [
            'state' => $state,
            'client_id' => $client->getKey(),
            'auth_token' => session('authToken'),
        ]);

        $response->assertRedirect();
        $this->assertStringContainsString('error=access_denied', $response->headers->get('Location'));
        $this->assertStringContainsString('state='.$state, $response->headers->get('Location'));
    }

    public function test_the_refresh_token_gives_a_new_access_token(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();
        $state = Str::random(40);

        $code = $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $state)), $state);
        $refreshToken = $this->exchange($client, $code)->assertOk()->json('refresh_token');

        $accessToken = $this->post('/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $client->getKey(),
            'client_secret' => $client->plainSecret,
            'refresh_token' => $refreshToken,
        ])->assertOk()->json('access_token');

        $this->apiUser($accessToken)->assertOk()->assertJsonPath('id', $user->id);
    }

    public function test_api_user_needs_a_valid_token(): void
    {
        $this->getJson('/api/user')->assertUnauthorized();

        $this->apiUser('not-a-token')->assertUnauthorized();
    }

    public function test_logging_out_of_the_server_revokes_what_it_issued(): void
    {
        $client = $this->makeClient();
        $user = User::factory()->create();
        $state = Str::random(40);

        $code = $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $state)), $state);
        $accessToken = $this->exchange($client, $code)->assertOk()->json('access_token');

        // A second code that the client never exchanged.
        $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $other = Str::random(40))), $other);

        $this->actingAs($user)->post('/logout')->assertRedirect('/');
        $this->assertGuest();

        $this->assertSame(0, Passport::token()->newQuery()->where('user_id', $user->id)->where('revoked', false)->count());
        $this->assertSame(0, Passport::refreshToken()->newQuery()->where('revoked', false)->count());
        $this->assertSame(0, Passport::authCode()->newQuery()->where('user_id', $user->id)->where('revoked', false)->count());

        $this->apiUser($accessToken)->assertUnauthorized();
    }

    public function test_the_upgrade_migration_hashes_plain_text_client_secrets(): void
    {
        // A client as Passport 10 stored it: legacy columns, secret in plain text.
        DB::table('oauth_clients')->insert([
            'id' => $id = (string) Str::uuid(),
            'name' => 'Old client',
            'secret' => $secret = Str::random(40),
            'redirect' => self::REDIRECT,
            'personal_access_client' => false,
            'password_client' => false,
            'revoked' => false,
            'created_at' => now(),
            'updated_at' => now(),
        ]);

        $migration = require database_path('migrations/2026_11_27_000001_hash_oauth_client_secrets.php');
        $migration->up();
        $migration->up(); // A second run leaves the hash alone.

        $stored = DB::table('oauth_clients')->where('id', $id)->value('secret');
        $this->assertNotSame($secret, $stored);
        $this->assertTrue(Hash::check($secret, $stored));

        // The old client (trusted by the column default) still completes the flow with its plain secret.
        $client = Client::findOrFail($id);
        $this->assertTrue($client->trusted);

        $user = User::factory()->create();
        $state = Str::random(40);
        $code = $this->codeFrom($this->actingAs($user)->get($this->authorizeQuery($client, $state)), $state);

        $this->exchange($client, $code, $secret)->assertOk();
    }
}
