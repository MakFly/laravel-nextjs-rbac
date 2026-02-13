<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use Pusher\Pusher;
use Ratchet\Client\Connector;
use Ratchet\Client\WebSocket;
use React\EventLoop\Loop;

class StreamOrderBook extends Command
{
    protected $signature = 'orderbook:stream
        {symbol=btcusdt : Trading pair symbol (e.g. btcusdt)}
        {--depth=20 : Order book depth (5, 10, or 20)}
        {--throttle=1000 : Minimum ms between broadcasts}';

    protected $description = 'Stream Binance order book data via Reverb WebSocket';

    private float $lastBroadcast = 0;

    private int $reconnectDelay = 1;

    private int $broadcastCount = 0;

    private Pusher $pusher;

    private const MAX_RECONNECT_DELAY = 30;

    private const RECONNECT_BEFORE_24H = 82800; // 23h in seconds

    public function handle(): int
    {
        $symbol = strtolower($this->argument('symbol'));
        $depth = (int) $this->option('depth');
        $throttle = (int) $this->option('throttle');

        $this->pusher = new Pusher(
            config('broadcasting.connections.reverb.key'),
            config('broadcasting.connections.reverb.secret'),
            config('broadcasting.connections.reverb.app_id'),
            [
                'host' => config('broadcasting.connections.reverb.options.host'),
                'port' => config('broadcasting.connections.reverb.options.port'),
                'scheme' => config('broadcasting.connections.reverb.options.scheme'),
                'useTLS' => config('broadcasting.connections.reverb.options.useTLS'),
            ]
        );

        $this->info("Starting OrderBook stream for {$symbol} (depth={$depth}, throttle={$throttle}ms)");

        $this->connect($symbol, $depth, $throttle);

        return self::SUCCESS;
    }

    private function connect(string $symbol, int $depth, int $throttle): void
    {
        $loop = Loop::get();
        $connector = new Connector($loop);

        $url = "wss://stream.binance.com:9443/ws/{$symbol}@depth{$depth}@100ms";
        $this->info("Connecting to {$url}");

        $connector($url)->then(
            function (WebSocket $conn) use ($symbol, $depth, $throttle, $loop) {
                $this->info('Connected to Binance WebSocket');
                $this->reconnectDelay = 1;

                // Graceful reconnect timer before Binance 24h limit
                $reconnectTimer = $loop->addTimer(self::RECONNECT_BEFORE_24H, function () use ($conn, $symbol, $depth, $throttle) {
                    $this->warn('Approaching 24h limit, reconnecting...');
                    $conn->close();
                    $this->connect($symbol, $depth, $throttle);
                });

                $conn->on('message', function ($msg) use ($throttle) {
                    $now = microtime(true) * 1000;

                    if (($now - $this->lastBroadcast) < $throttle) {
                        return;
                    }

                    $data = json_decode((string) $msg, true);
                    if (! $data || ! isset($data['bids'], $data['asks'])) {
                        return;
                    }

                    $bids = array_map(fn ($b) => ['price' => $b[0], 'qty' => $b[1]], $data['bids']);
                    $asks = array_map(fn ($a) => ['price' => $a[0], 'qty' => $a[1]], $data['asks']);

                    try {
                        $this->pusher->trigger('orderbook', 'OrderBookUpdated', [
                            'bids' => $bids,
                            'asks' => $asks,
                            'lastUpdateId' => $data['lastUpdateId'] ?? 0,
                            'timestamp' => (int) (microtime(true) * 1000),
                        ]);

                        $this->broadcastCount++;
                        if ($this->broadcastCount % 10 === 0) {
                            $this->line("Broadcasted {$this->broadcastCount} updates");
                        }
                    } catch (\Pusher\ApiErrorException $e) {
                        if ($this->broadcastCount === 0) {
                            $this->error("Cannot reach Reverb: {$e->getMessage()}");
                            $this->warn('Make sure Reverb is running: make dev-reverb');
                        }
                    }

                    $this->lastBroadcast = $now;
                });

                $conn->on('close', function ($code = null, $reason = null) use ($loop, $symbol, $depth, $throttle, $reconnectTimer) {
                    $loop->cancelTimer($reconnectTimer);
                    $this->warn("Connection closed (code={$code}, reason={$reason}). Reconnecting in {$this->reconnectDelay}s...");

                    $loop->addTimer($this->reconnectDelay, function () use ($symbol, $depth, $throttle) {
                        $this->connect($symbol, $depth, $throttle);
                    });

                    $this->reconnectDelay = min($this->reconnectDelay * 2, self::MAX_RECONNECT_DELAY);
                });

                $conn->on('error', function (\Exception $e) {
                    $this->error('WebSocket error: '.$e->getMessage());
                });
            },
            function (\Exception $e) use ($loop, $symbol, $depth, $throttle) {
                $this->error("Connection failed: {$e->getMessage()}. Retrying in {$this->reconnectDelay}s...");

                $loop->addTimer($this->reconnectDelay, function () use ($symbol, $depth, $throttle) {
                    $this->connect($symbol, $depth, $throttle);
                });

                $this->reconnectDelay = min($this->reconnectDelay * 2, self::MAX_RECONNECT_DELAY);
            }
        );

        $loop->run();
    }
}
