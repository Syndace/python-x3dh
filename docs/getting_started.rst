Getting Started
===============

This quick start guide assumes basic knowledge of the `X3DH key agreement protocol <https://www.signal.org/docs/specifications/x3dh/>`_.

The class :class:`x3dh.state.State` builds the core of this library. To use it, create a subclass and override the :meth:`~x3dh.state.State._publish_bundle` and :meth:`~x3dh.state.State._encode_public_key` methods. You can now create instances using the :meth:`~x3dh.state.State.create` method. This method requires a set of configuration parameters, most of them directly correspond to those parameters defined in the X3DH specification. Two parameters provide configuration that goes beyond the specification: ``internal_ik_type`` and ``external_ik_type``.

.. _ik-types:

In the X3DH specification, the identity key is a Curve25519/Curve448 key and `XEdDSA <https://www.signal.org/docs/specifications/xeddsa/>`_ is used to create signatures with it. This library is a little more flexible regarding the identity key. First, you can choose whether to use a Curve25519/Curve448 or an Ed25519/Ed448 key pair for the identity key internally using ``internal_ik_type``. Second, you can choose whether the public part of the identity key in the bundle is transferred as Curve25519/Curve448 or Ed25519/Ed448 using ``external_ik_type``. Thus, there are four possible combinations of internal and external identity key types. One of these combinations is forbidden: Ed25519/Ed448 internally and Curve25519/Curve448 externally. Note that Curve448/Ed448 is currently not supported.
