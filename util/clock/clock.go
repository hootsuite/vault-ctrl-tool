package clock

import (
	"context"
	"time"

	"k8s.io/utils/clock"
)

// using these utility methods, a FakeClock (NewFakeClock) can be "injected" via a context.Context. Code that needs
// the current time can call "clock.Now(ctx)". Note that I'm using the Kubernetes "utils/clock", which also has
// support for a bunch of other methods that I haven't proxied here.

var contextKey = "vctClock"

type Factory func(ctx context.Context) clock.Clock

func Now(ctx context.Context) time.Time {
	return Get(ctx).Now()
}

func SetFactory(ctx context.Context, f Factory) context.Context {
	return context.WithValue(ctx, &contextKey, f)
}

// Set creates a new Context using the supplied Clock.
func Set(ctx context.Context, c clock.Clock) context.Context {
	return SetFactory(ctx, func(context.Context) clock.Clock { return c })
}

func Get(ctx context.Context) clock.Clock {
	if v := ctx.Value(&contextKey); v != nil {
		if f, ok := v.(Factory); ok {
			return f(ctx)
		}
	}
	return clock.RealClock{}
}
