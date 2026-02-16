<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;

class UserController extends Controller
{
    public function index(): JsonResponse
    {
        $users = User::with('roles')->get()->map(function ($user) {
            $userData = $user->toArray();
            $userData['roles'] = $user->roles->map(fn ($role) => [
                'id' => $role->id,
                'name' => $role->name,
                'slug' => $role->name,
            ]);

            return $userData;
        });

        return response()->json([
            'data' => $users,
        ]);
    }
}
