<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Spatie\Permission\PermissionRegistrar;

class UserController extends Controller
{
    public function index(): JsonResponse
    {
        return response()->json([
            'data' => User::with('roles')->paginate(15),
        ]);
    }

    public function show(User $user): JsonResponse
    {
        return response()->json([
            'data' => $user->load('roles.permissions'),
        ]);
    }

    public function assignRole(User $user, Request $request): JsonResponse
    {
        $validated = $request->validate(['role' => 'required|string|exists:roles,name']);
        $user->assignRole($validated['role']);
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        return response()->json(['message' => 'Role assigned', 'data' => $user->load('roles')]);
    }

    public function removeRole(User $user, \Spatie\Permission\Models\Role $role): JsonResponse
    {
        $user->removeRole($role);
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        return response()->json(['message' => 'Role removed']);
    }
}
