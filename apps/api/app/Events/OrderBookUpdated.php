<?php

namespace App\Events;

use Illuminate\Broadcasting\Channel;
use Illuminate\Contracts\Broadcasting\ShouldBroadcastNow;

class OrderBookUpdated implements ShouldBroadcastNow
{
    public function __construct(
        public array $bids,
        public array $asks,
        public int $lastUpdateId,
        public int $timestamp,
    ) {}

    public function broadcastOn(): Channel
    {
        return new Channel('orderbook');
    }

    public function broadcastAs(): string
    {
        return 'OrderBookUpdated';
    }

    public function broadcastWith(): array
    {
        return [
            'bids' => $this->bids,
            'asks' => $this->asks,
            'lastUpdateId' => $this->lastUpdateId,
            'timestamp' => $this->timestamp,
        ];
    }
}
