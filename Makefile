.PHONY: build clean

# Compiles the binary into the build/ directory
build:
	go build -o build/BitcoinParser .

# Deletes the build directory to start fresh
clean:
	rm -rf build/
