#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Typed pipeline exceptions. Library functions must not call sys.exit()."""

class PipelineError(Exception):
    pass

class DecodeError(PipelineError):
    pass

class ParsePipelineError(PipelineError):
    pass

class VllmUnavailableError(PipelineError):
    pass

class PipelineCancelled(PipelineError):
    pass

class ConfigurationError(PipelineError):
    pass
