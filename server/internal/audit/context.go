package audit

import "context"

type actorContextKey struct{}

// WithActor attaches a trusted server-derived actor to a request context.
func WithActor(ctx context.Context, actor Actor) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, actorContextKey{}, actor)
}

// ActorFromContext returns the trusted actor attached by an authentication
// boundary. It never consults request headers or other caller-supplied values.
func ActorFromContext(ctx context.Context) (Actor, bool) {
	if ctx == nil {
		return Actor{}, false
	}
	actor, ok := ctx.Value(actorContextKey{}).(Actor)
	if !ok || actor.ID == "" {
		return Actor{}, false
	}
	switch actor.Kind {
	case ActorOperator, ActorAgent, ActorSystem:
		return actor, true
	default:
		return Actor{}, false
	}
}

// ActorOr returns a trusted contextual actor or the supplied server-owned
// fallback.
func ActorOr(ctx context.Context, fallback Actor) Actor {
	if actor, ok := ActorFromContext(ctx); ok {
		return actor
	}
	return fallback
}

func DefaultOperatorActor() Actor {
	return Actor{Kind: ActorOperator, ID: "unspecified"}
}

func DefaultSystemActor() Actor {
	return Actor{Kind: ActorSystem, ID: "microc2-server"}
}
