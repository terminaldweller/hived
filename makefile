DST_DIR?=./protobuf
SRC_DIR?=./protobuf
PROTOBUF_SRC_LIST:=$(shell find ./protobuf -name '*.proto' )
ARTIFACT_LIST:=$(patsubst %.proto, %.pb.go, $(shell find ./protobuf -name '*.proto'))

DEFAULT: default

default: $(ARTIFACT_LIST)

$(SRC_DIR)/%.pb.go:$(SRC_DIR)/%.proto
	protoc --proto_path=$(SRC_DIR) --go_out=$(DST_DIR) $<

clean:
	- rm $(ARTIFACT_LIST)
