<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Spatie\Permission\Models\Permission;
use Spatie\Permission\Models\Role;
use Spatie\Permission\PermissionRegistrar;

class RoleController extends Controller
{
    public function index(): JsonResponse
    {
        $roles = Role::where('guard_name', 'api')
            ->with('permissions')
            ->get()
            ->map(function ($role) {
                return [
                    'id' => $role->id,
                    'name' => $role->name,
                    'slug' => $role->name,
                    'description' => null,
                    'created_at' => $role->created_at,
                    'updated_at' => $role->updated_at,
                    'permissions' => $role->permissions->map(function ($perm) {
                        $parts = explode('.', $perm->name);
                        return [
                            'id' => $perm->id,
                            'name' => $perm->name,
                            'slug' => $perm->name,
                            'resource' => $parts[0] ?? '',
                            'action' => $parts[1] ?? '',
                        ];
                    }),
                ];
            });

        return response()->json([
            'data' => $roles,
        ]);
    }

    public function store(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255|unique:roles,name',
        ]);

        $role = Role::create([
            'name' => $validated['name'],
            'guard_name' => 'api',
        ]);

        return response()->json([
            'data' => [
                'id' => $role->id,
                'name' => $role->name,
                'slug' => $role->name,
                'description' => null,
                'created_at' => $role->created_at,
                'updated_at' => $role->updated_at,
            ],
        ], 201);
    }

    public function updatePermissions(Role $role, Request $request): JsonResponse
    {
        $validated = $request->validate(['permissions' => 'required|array']);

        $permissionNames = Permission::whereIn('id', $validated['permissions'])
            ->where('guard_name', 'api')
            ->pluck('name');

        $role->syncPermissions($permissionNames);
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        $role->load('permissions');

        return response()->json([
            'message' => 'Permissions updated',
            'data' => [
                'id' => $role->id,
                'name' => $role->name,
                'slug' => $role->name,
                'description' => null,
                'created_at' => $role->created_at,
                'updated_at' => $role->updated_at,
                'permissions' => $role->permissions->map(function ($perm) {
                    $parts = explode('.', $perm->name);
                    return [
                        'id' => $perm->id,
                        'name' => $perm->name,
                        'slug' => $perm->name,
                        'resource' => $parts[0] ?? '',
                        'action' => $parts[1] ?? '',
                    ];
                }),
            ],
        ]);
    }
}
