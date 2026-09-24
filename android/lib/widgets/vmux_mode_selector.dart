import 'package:flutter/material.dart';

import '../runtime/runtime_snapshot.dart';

class VmuxModeSelector extends StatelessWidget {
  const VmuxModeSelector({
    super.key,
    required this.snapshot,
    required this.selectedMode,
    required this.onChanged,
    this.experimental = false,
  });

  final RuntimeSnapshot snapshot;
  final String selectedMode;
  final ValueChanged<String> onChanged;
  final bool experimental;

  @override
  Widget build(BuildContext context) {
    final modes = snapshot.availableMuxModes(experimental: experimental);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        DropdownButtonFormField<String>(
          value: modes.contains(selectedMode) ? selectedMode : null,
          hint: const Text('Unavailable'),
          decoration: const InputDecoration(
            labelText: 'VMUX mode',
            border: OutlineInputBorder(),
          ),
          items: modes
              .map((mode) => DropdownMenuItem(
                    value: mode,
                    child: Text(
                      mode == 'compat' ? 'Compatibility mode' : mode,
                    ),
                  ))
              .toList(growable: false),
          onChanged: (mode) {
            if (mode != null) onChanged(mode);
          },
        ),
        const SizedBox(height: 6),
        const Text('Takes effect on next connection'),
        if (snapshot.effectiveMuxMode.isNotEmpty)
          Text('Effective now: ${snapshot.effectiveMuxDisplayName}'),
      ],
    );
  }
}
