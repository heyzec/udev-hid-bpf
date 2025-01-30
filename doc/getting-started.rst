.. _getting_started:

Getting started
===============

If you just want to test a pre-built binary from our CI, please see :ref:`installing_from_ci`.

.. _dependencies:

Dependencies
------------

- ``rust``: install through your package manager or with ``rustup``:

.. code-block:: console

   $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   $ source "$HOME/.cargo/env"

- ``udev`` and ``llvm``: Check the `.gitlab-ci.yml <https://gitlab.freedesktop.org/libevdev/udev-hid-bpf/-/blob/main/.gitlab-ci.yml>`_ for ``FEDORA_PACKAGES``.

Building all files
------------------

Clone the repo, ``cd`` into it, and build the loader *and* the various example HID-BPF programs
using a standard `meson <https://mesonbuild.com/>`_ build process:

.. code:: console

   $ git clone https://gitlab.freedesktop.org/libevdev/udev-hid-bpf.git
   $ cd udev-hid-bpf/
   $ meson setup builddir -Dbpfs=testing,stable,userhacks
   $ meson compile -C builddir

The above ``meson`` commands will build the tool and any BPF programs it finds in ``src/bpf/*.bpf.c``.

.. note:: Typically users would rely on the distribution to ship the ``stable`` set of
          BPFs. By default ``udev-hid-bpf`` builds only the ``testing`` and
          ``userhacks`` section. See :ref:`stable_testing_userhacks` for details.

Please see the `meson documentation <https://mesonbuild.com/>`_ for more details on invoking ``meson``.

.. _installation:

Install all files
-----------------

.. note:: The default meson invocation only installs the "testing" ``.bpf.o`` files (see :ref:`here  <stable_testing_userhacks>`).

We can install the binary with the following command:

.. code-block:: console

   $ meson install -C builddir
   ... this will ask for your sudo password to install udev rules and hwdb files

The above command will (re)build the tool and any BPF programs it finds in ``src/bpf/*.bpf.c``.
It will then install

- the tool itself into in ``/usr/local/bin``
- the compiled BPF objects in ``/usr/local/lib/firmware/hid/bpf``.
- a hwdb entry to tag matching devices in ``/etc/udev/hwdb.d/81-hid-bpf.hwdb``
- a udev rule to trigger the tool in ``/etc/udev/rules.d/81-hid-bpf.rules``

Passing the ``--prefix`` option to ``meson setup`` will of course change the above paths.

.. _install_specific:

Install a specific ``bpf.o`` file only
--------------------------------------

In many cases a user only wants to install a single file for testing. The
easiest approach is to use ``udev-hid-bpf`` to install it:

.. code:: console

  $ ./builddir/udev-hid-bpf install ./builddir/src/bpf/my_awesome_hid_bpf_filter.bpf.o

or to install udev-hid-bpf itself too:

.. code:: console

  $ ./builddir/udev-hid-bpf install --install-exe ./builddir/src/bpf/my_awesome_hid_bpf_filter.bpf.o

This will install the ``.bpf.o`` file into ``/etc/udev-hid-bpf/`` and also
install a custom udev rule udev for this file. If ``--install-exe`` is given,
``udev-hid-bpf`` will also install itself in the given prefix's bindir (``/usr/local/bin`` by default) if required.


Running the BPF program
-----------------------

Once installed, unplug/replug any supported device, and the BPF program will automatically be attached to the HID kernel device.
