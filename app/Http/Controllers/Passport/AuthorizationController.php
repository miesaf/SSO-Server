<?php

namespace App\Http\Controllers\Passport;

use Illuminate\Http\Request;
use Illuminate\Support\Str;
use Laravel\Passport\TokenRepository;
use Laravel\Passport\ClientRepository;
use Psr\Http\Message\ServerRequestInterface;

use Laravel\Passport\Http\Controllers\AuthorizationController as OauthAuthorizationController;

class AuthorizationController extends OauthAuthorizationController
{
    /**
     * Authorize a client to access the user's account.
     *
     * @param  \Psr\Http\Message\ServerRequestInterface  $psrRequest
     * @param  \Illuminate\Http\Request  $request
     * @param  \Laravel\Passport\ClientRepository  $clients
     * @param  \Laravel\Passport\TokenRepository  $tokens
     * @return \Illuminate\Http\Response
     */
    public function authorize(ServerRequestInterface $psrRequest,
        Request $request,
        ClientRepository $clients,
        TokenRepository $tokens)
    {
        return $this->withErrorHandling(function () use ($psrRequest, $request, $clients, $tokens) {
            $authRequest = $this->server->validateAuthorizationRequest($psrRequest);

            $scopes = $this->parseScopes($authRequest);

            $token = $tokens->findValidToken(
                $user = $request->user(),
                $client = $clients->find($authRequest->getClient()->getIdentifier())
            );

            $trusted_client = (boolean)$client->trusted;

            if (($token && $token->scopes === collect($scopes)->pluck('id')->all()) || $trusted_client) {
                return $this->approveRequest($authRequest, $user);
            }

            $log_info = [
                'trusted_client' => $trusted_client,
                'client' => $client,
            ];

            \Log::info('Oauth Authorize client login ...', $log_info);

            $request->session()->put('authToken', $authToken = Str::random());
            $request->session()->put('authRequest', $authRequest);

            return $this->response->view('passport::authorize', [
                'client' => $client,
                'user' => $user,
                'scopes' => $scopes,
                'request' => $request,
                'authToken' => $authToken,
            ]);
        });
    }
}
