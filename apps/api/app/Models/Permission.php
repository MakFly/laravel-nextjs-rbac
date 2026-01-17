<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

class Permission extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'slug',
        'resource',
        'action',
        'description',
    ];

    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(Role::class);
    }

    public static function createForResource(string $resource, array $actions = ['create', 'read', 'update', 'delete']): void
    {
        foreach ($actions as $action) {
            self::firstOrCreate(
                ['resource' => $resource, 'action' => $action],
                [
                    'name' => ucfirst($action) . ' ' . ucfirst($resource),
                    'slug' => "{$resource}.{$action}",
                ]
            );
        }
    }
}
