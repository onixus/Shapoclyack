"""Standard-library contracts shared by the API and standalone sensor.

The package lives inside the signed sensor tree so updates keep one atomic
owner. Importing it must not load the worker, scanner, or control-plane models.
"""
