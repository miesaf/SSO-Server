<?php

namespace Tests\Feature;

use App\Models\User;
use Illuminate\Auth\Notifications\ResetPassword;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Notification;
use Tests\TestCase;

class WebPagesTest extends TestCase
{
    use RefreshDatabase;

    public function test_the_welcome_page_offers_login_and_register_to_guests(): void
    {
        $this->get('/')
            ->assertOk()
            ->assertSee('Single Sign On (SSO) Server')
            ->assertSee(route('login'), false)
            ->assertSee(route('register'), false);
    }

    public function test_the_welcome_page_links_home_when_signed_in(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/')
            ->assertOk()
            ->assertSee(route('home'), false);
    }

    public function test_guest_pages_render(): void
    {
        foreach (['/login', '/register', '/password/reset'] as $url) {
            $this->get($url)->assertOk();
        }
    }

    public function test_home_needs_a_login(): void
    {
        $this->get('/home')->assertRedirect('/login');

        $user = User::factory()->create();

        $this->actingAs($user)->get('/home')
            ->assertOk()
            ->assertSee('You are logged in!')
            ->assertSee($user->name);
    }

    public function test_signed_in_users_are_kept_away_from_login_and_register(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->get('/login')->assertRedirect('/home');
        $this->actingAs($user)->get('/register')->assertRedirect('/home');
    }

    public function test_a_user_can_log_in_and_out(): void
    {
        $user = User::factory()->create();

        $this->post('/login', ['email' => $user->email, 'password' => 'wrong'])
            ->assertSessionHasErrors('email');
        $this->assertGuest();

        $this->post('/login', ['email' => $user->email, 'password' => 'password'])
            ->assertRedirect('/home');
        $this->assertAuthenticatedAs($user);

        $this->post('/logout')->assertRedirect('/');
        $this->assertGuest();
    }

    public function test_a_visitor_can_register(): void
    {
        $this->post('/register', [
            'name' => 'New User',
            'email' => 'new@example.com',
            'password' => 'secret-password',
            'password_confirmation' => 'secret-password',
        ])->assertRedirect('/home');

        $user = User::where('email', 'new@example.com')->firstOrFail();
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(Hash::check('secret-password', $user->password));
    }

    public function test_a_user_can_reset_a_forgotten_password(): void
    {
        Notification::fake();
        $user = User::factory()->create();

        $this->post('/password/email', ['email' => $user->email])->assertSessionHas('status');

        $token = null;
        Notification::assertSentTo($user, ResetPassword::class, function (ResetPassword $notification) use (&$token) {
            $token = $notification->token;

            return true;
        });

        $this->get('/password/reset/'.$token.'?email='.urlencode($user->email))->assertOk();

        $this->post('/password/reset', [
            'token' => $token,
            'email' => $user->email,
            'password' => 'brand-new-password',
            'password_confirmation' => 'brand-new-password',
        ])->assertRedirect('/home');

        $this->assertTrue(Hash::check('brand-new-password', $user->fresh()->password));
    }
}
