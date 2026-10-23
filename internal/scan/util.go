package scan

import (
	"context"
	"time"
)

func contextWithTimeout(ctx context.Context, seconds int) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
}
