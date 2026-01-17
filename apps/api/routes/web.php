<?php

use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return response()->json([
        'message' => 'API OK',
        'version' => '1.0.0',
        'framework' => 'Laravel',
    ]);
});
