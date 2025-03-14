package tracing

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/spf13/viper"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/log/global"
	otelmetric "go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type Tracing struct {
	Tracer oteltrace.Tracer
	Meter  otelmetric.Meter
	Logger *slog.Logger
}

// setupOTelSDK bootstraps the OpenTelemetry pipeline.
// If it does not return an error, make sure to call shutdown for proper cleanup.
func SetupOTelSDK(ctx context.Context) (shutdown func(context.Context) error, err error) {
	var shutdownFuncs []func(context.Context) error

	// shutdown calls cleanup functions registered via shutdownFuncs.
	// The errors from the calls are joined.
	// Each registered cleanup will be invoked once.
	shutdown = func(ctx context.Context) error {
		var err error
		for _, fn := range shutdownFuncs {
			err = errors.Join(err, fn(ctx))
		}
		shutdownFuncs = nil
		return err
	}

	// handleErr calls shutdown for cleanup and makes sure that all errors are returned.
	handleErr := func(inErr error) {
		err = errors.Join(inErr, shutdown(ctx))
	}

	// Set up propagator.
	prop := NewPropagator()
	otel.SetTextMapPropagator(prop)

	// Set up trace provider.
	tracerProvider, err := NewTracerProvider()
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, tracerProvider.Shutdown)
	otel.SetTracerProvider(tracerProvider)

	// Set up meter provider.
	meterProvider, err := NewMeterProvider()
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, meterProvider.Shutdown)
	otel.SetMeterProvider(meterProvider)

	// Set up logger provider.
	loggerProvider, err := NewLoggerProvider()
	if err != nil {
		handleErr(err)
		return
	}
	shutdownFuncs = append(shutdownFuncs, loggerProvider.Shutdown)
	global.SetLoggerProvider(loggerProvider)

	return
}

func NewPropagator() propagation.TextMapPropagator {
	return propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
}

func NewTracerProvider() (*trace.TracerProvider, error) {
	ctx := context.Background()
	traceExporter, err := otlptracegrpc.New(
		ctx,
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithEndpoint(viper.GetString("OTEL_EXPORTER_OTLP_ENDPOINT")),
	)
	if err != nil {
		return nil, err
	}
	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(viper.GetString("APP_NAME")),
		semconv.ServiceVersionKey.String(viper.GetString("APP_VERSION")),
	)
	tracerProvider := trace.NewTracerProvider(
		trace.WithBatcher(
			traceExporter,
			// Default is 5s. Set to 1s for demonstrative purposes.
			trace.WithBatchTimeout(5*time.Second),
			// trace.WithBatchTimeout(time.Second),
		),
		trace.WithResource(resource),
	)
	return tracerProvider, nil
}

func NewMeterProvider() (*metric.MeterProvider, error) {
	ctx := context.Background()
	metricExporter, err := otlpmetricgrpc.New(
		ctx,
		otlpmetricgrpc.WithInsecure(),
		otlpmetricgrpc.WithEndpoint(viper.GetString("OTEL_EXPORTER_OTLP_ENDPOINT")),
	)
	if err != nil {
		return nil, err
	}
	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(viper.GetString("APP_NAME")),
		semconv.ServiceVersionKey.String(viper.GetString("APP_VERSION")),
	)

	meterProvider := metric.NewMeterProvider(
		metric.WithReader(metric.NewPeriodicReader(
			metricExporter,
			// Default is 1m. Set to 1s for demonstrative purposes.
			metric.WithInterval(time.Second)),
		),
		metric.WithResource(resource),
	)
	return meterProvider, nil
}

func NewLoggerProvider() (*log.LoggerProvider, error) {
	ctx := context.Background()
	logExporter, err := otlploggrpc.New(
		ctx,
		otlploggrpc.WithInsecure(),
		otlploggrpc.WithEndpoint(viper.GetString("OTEL_EXPORTER_OTLP_ENDPOINT")),
	)
	if err != nil {
		return nil, err
	}
	resource := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(viper.GetString("APP_NAME")),
		semconv.ServiceVersionKey.String(viper.GetString("APP_VERSION")),
	)
	loggerProvider := log.NewLoggerProvider(
		log.WithProcessor(log.NewBatchProcessor(
			logExporter,
			log.WithExportInterval(time.Second), // min & default: 1s
		)),
		log.WithResource(resource),
	)
	return loggerProvider, nil
}

func InitTracer(name string) oteltrace.Tracer {
	return otel.Tracer(name)
}

func InitMeter(name string) otelmetric.Meter {
	return otel.Meter(name)
}

func InitLogger(name string) *slog.Logger {
	handler := otelslog.NewHandler(name, otelslog.WithLoggerProvider(global.GetLoggerProvider()))
	return slog.New(handler)
}

func InitTracing(name string) (oteltrace.Tracer, otelmetric.Meter, *slog.Logger) {
	// TODO: update to multi handler
	handler := otelslog.NewHandler(name, otelslog.WithLoggerProvider(global.GetLoggerProvider()))
	// handler := slog.NewJSONHandler(os.Stdout, nil)
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return otel.Tracer(name), otel.Meter(name), logger
}

// RecordError is a utility function to record errors in OpenTelemetry traces
func RecordError(ctx context.Context, err error, attrs ...attribute.KeyValue) {
	if err == nil {
		return
	}

	// Get the active span from context
	span := oteltrace.SpanFromContext(ctx)
	if !span.SpanContext().IsValid() {
		return
	}

	// Record the error in the span
	span.RecordError(err)

	// Set attributes for additional error metadata
	span.SetAttributes(
		attribute.String("error.message", err.Error()),
		attribute.Bool("error.occurred", true),
	)
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}

	// Set the span status to error
	span.SetStatus(codes.Error, err.Error())
}

type Transport struct {
	Base http.RoundTripper
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	// Start a new span for the outgoing request
	tracer := otel.Tracer("openapi-client")
	ctx, span := tracer.Start(ctx, "HTTP "+req.Method)
	defer span.End()

	// Inject trace context into request headers
	propagator := otel.GetTextMapPropagator()
	propagator.Inject(ctx, propagation.HeaderCarrier(req.Header))

	// Forward the request using the original transport
	return t.Base.RoundTrip(req)
}
