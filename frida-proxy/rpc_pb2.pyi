from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class InstallStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    INSTALL_OK: _ClassVar[InstallStatus]
    INSTALL_ERROR: _ClassVar[InstallStatus]
    INSTALL_ALREADY_INSTALLED: _ClassVar[InstallStatus]
    INSTALL_ERR_NO_DEVICES: _ClassVar[InstallStatus]

class EvalStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    EVAL_OK: _ClassVar[EvalStatus]
    EVAL_ERROR: _ClassVar[EvalStatus]
    EVAL_ERR_PACKAGE_NOT_FOUND: _ClassVar[EvalStatus]
    EVAL_ERR_TIMEOUT: _ClassVar[EvalStatus]
    EVAL_ERR_PROCESS_CRASHED: _ClassVar[EvalStatus]
    EVAL_ERR_SCRIPT_ERROR: _ClassVar[EvalStatus]
    EVAL_ERR_FRIDA_ERROR: _ClassVar[EvalStatus]
    EVAL_ERR_SPAWN_FAILED: _ClassVar[EvalStatus]
INSTALL_OK: InstallStatus
INSTALL_ERROR: InstallStatus
INSTALL_ALREADY_INSTALLED: InstallStatus
INSTALL_ERR_NO_DEVICES: InstallStatus
EVAL_OK: EvalStatus
EVAL_ERROR: EvalStatus
EVAL_ERR_PACKAGE_NOT_FOUND: EvalStatus
EVAL_ERR_TIMEOUT: EvalStatus
EVAL_ERR_PROCESS_CRASHED: EvalStatus
EVAL_ERR_SCRIPT_ERROR: EvalStatus
EVAL_ERR_FRIDA_ERROR: EvalStatus
EVAL_ERR_SPAWN_FAILED: EvalStatus

class InstallRequest(_message.Message):
    __slots__ = ("package_path",)
    PACKAGE_PATH_FIELD_NUMBER: _ClassVar[int]
    package_path: str
    def __init__(self, package_path: _Optional[str] = ...) -> None: ...

class InstallReply(_message.Message):
    __slots__ = ("status", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: InstallStatus
    error: str
    def __init__(self, status: _Optional[_Union[InstallStatus, str]] = ..., error: _Optional[str] = ...) -> None: ...

class EvalRequest(_message.Message):
    __slots__ = ("package_name", "class_name", "method_name", "method_signature", "method_args")
    PACKAGE_NAME_FIELD_NUMBER: _ClassVar[int]
    CLASS_NAME_FIELD_NUMBER: _ClassVar[int]
    METHOD_NAME_FIELD_NUMBER: _ClassVar[int]
    METHOD_SIGNATURE_FIELD_NUMBER: _ClassVar[int]
    METHOD_ARGS_FIELD_NUMBER: _ClassVar[int]
    package_name: str
    class_name: str
    method_name: str
    method_signature: str
    method_args: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, package_name: _Optional[str] = ..., class_name: _Optional[str] = ..., method_name: _Optional[str] = ..., method_signature: _Optional[str] = ..., method_args: _Optional[_Iterable[str]] = ...) -> None: ...

class EvalReply(_message.Message):
    __slots__ = ("status", "result", "error")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    RESULT_FIELD_NUMBER: _ClassVar[int]
    ERROR_FIELD_NUMBER: _ClassVar[int]
    status: EvalStatus
    result: str
    error: str
    def __init__(self, status: _Optional[_Union[EvalStatus, str]] = ..., result: _Optional[str] = ..., error: _Optional[str] = ...) -> None: ...
