# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

from . import rpc_pb2 as rpc__pb2

GRPC_GENERATED_VERSION = '1.65.5'
GRPC_VERSION = grpc.__version__
EXPECTED_ERROR_RELEASE = '1.66.0'
SCHEDULED_RELEASE_DATE = 'August 6, 2024'
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    warnings.warn(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in rpc_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
        + f' This warning will become an error in {EXPECTED_ERROR_RELEASE},'
        + f' scheduled for release on {SCHEDULED_RELEASE_DATE}.',
        RuntimeWarning
    )


class FridaEvalProxyStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.install = channel.unary_unary(
                '/frida_eval.FridaEvalProxy/install',
                request_serializer=rpc__pb2.InstallRequest.SerializeToString,
                response_deserializer=rpc__pb2.InstallReply.FromString,
                _registered_method=True)
        self.eval = channel.unary_unary(
                '/frida_eval.FridaEvalProxy/eval',
                request_serializer=rpc__pb2.EvalRequest.SerializeToString,
                response_deserializer=rpc__pb2.EvalReply.FromString,
                _registered_method=True)


class FridaEvalProxyServicer(object):
    """Missing associated documentation comment in .proto file."""

    def install(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def eval(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_FridaEvalProxyServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'install': grpc.unary_unary_rpc_method_handler(
                    servicer.install,
                    request_deserializer=rpc__pb2.InstallRequest.FromString,
                    response_serializer=rpc__pb2.InstallReply.SerializeToString,
            ),
            'eval': grpc.unary_unary_rpc_method_handler(
                    servicer.eval,
                    request_deserializer=rpc__pb2.EvalRequest.FromString,
                    response_serializer=rpc__pb2.EvalReply.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'frida_eval.FridaEvalProxy', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('frida_eval.FridaEvalProxy', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class FridaEvalProxy(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def install(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/frida_eval.FridaEvalProxy/install',
            rpc__pb2.InstallRequest.SerializeToString,
            rpc__pb2.InstallReply.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def eval(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/frida_eval.FridaEvalProxy/eval',
            rpc__pb2.EvalRequest.SerializeToString,
            rpc__pb2.EvalReply.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
