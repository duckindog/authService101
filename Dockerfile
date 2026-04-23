# --- Stage 1: Build the Go binary ---
FROM golang:1.24-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the binary. 
# CGO_ENABLED=0 ensures a static binary which is required for Alpine
RUN CGO_ENABLED=0 GOOS=linux go build -o authService101 ./cmd/server/main.go

# --- Stage 2: Create the final lightweight image ---
FROM alpine:latest

WORKDIR /root/

# Copy only the compiled binary from the builder stage
COPY --from=builder /app/authService101 .
COPY --from=builder /app/migrations ./migrations

# Expose the port your Go app listens on (adjust if you use a different port)
EXPOSE 8080

# Command to run the executable
CMD ["./authService101"]