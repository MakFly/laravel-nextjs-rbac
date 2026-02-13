<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Laravel\Passport\HasApiTokens;
use Spatie\Permission\Traits\HasRoles;

class User extends Authenticatable
{
    use HasApiTokens, HasFactory, HasRoles, Notifiable;

    // Force Spatie to always use 'api' guard for roles/permissions lookup,
    // regardless of which auth guard (web/api) authenticated the user.
    protected $guard_name = 'api';

    protected $fillable = [
        'name',
        'email',
        'password',
        'onboarding_status',
        'onboarding_step',
    ];

    protected $hidden = [
        'password',
        'remember_token',
    ];

    protected function casts(): array
    {
        return [
            'email_verified_at' => 'datetime',
            'password' => 'hashed',
        ];
    }

    // =========================================================================
    // Relations
    // =========================================================================

    public function oauthProviders(): HasMany
    {
        return $this->hasMany(OAuthProvider::class);
    }

    public function kycProfile(): HasOne
    {
        return $this->hasOne(KycProfile::class);
    }

    public function userOperation(): HasOne
    {
        return $this->hasOne(UserOperation::class);
    }

    public function onboardingDraft(): HasOne
    {
        return $this->hasOne(OnboardingDraft::class);
    }

    // =========================================================================
    // Convenience Methods
    // =========================================================================

    public function isAdmin(): bool
    {
        return $this->hasRole('admin');
    }

    public function hasPermissionForResource(string $resource, string $action): bool
    {
        return $this->hasPermissionTo("{$resource}.{$action}")
            || $this->hasPermissionTo("{$resource}.manage");
    }

    public function hasCompletedOnboarding(): bool
    {
        return $this->onboarding_status === 'completed';
    }
}
