<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

// The signed-in user behind a Passport access token (SSO clients call this after /oauth/token).
Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});
