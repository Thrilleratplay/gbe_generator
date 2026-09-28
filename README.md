# GBE generator
Intel Gigabit Ethernet firmware blob generator for 82579LM, 82579V, i217LM, i217V, i218LM, i218V, i219LM, or i219V

## Usage

_NOTE_: the MAC address is to be formatted without separator characters. Example `00deadc0ffee`

_NOTE_: The 82579LM and 82579V have a `--mobile` flag if used in a mobile/laptop device.  Default FALSE.

**82579LM**

`python gbe_generator.py --mac <MAC ADDRESS> --model 82579lm [--mobile] --filename <BLOB FILE NAME>`

**82579V**

`python gbe_generator.py --mac <MAC ADDRESS> --model 82579v [--mobile] --filename <BLOB FILE NAME>`

_NOTE_: The i217LM,i217V,i218LM,i218V,i219LM, and i219V have a `--lan-switch` flag to support a design that includes a LAN switch.  Default FALSE.

**i217LM**

`python gbe_generator.py --mac <MAC ADDRESS> --model i217lm [--lan-switch] --filename <BLOB FILE NAME>`

**i217V**

`python gbe_generator.py --mac <MAC ADDRESS> --model i217v [--lan-switch] --filename <BLOB FILE NAME>`

**i218LM**

`python gbe_generator.py --mac <MAC ADDRESS> --model i218lm [--lan-switch] --filename <BLOB FILE NAME>`

**i218V**

`python gbe_generator.py --mac <MAC ADDRESS> --model i218v [--lan-switch] --filename <BLOB FILE NAME>`

**i219LM**

`python gbe_generator.py --mac <MAC ADDRESS> --model i219lm [--lan-switch] --filename <BLOB FILE NAME>`

**i219V**

`python gbe_generator.py --mac <MAC ADDRESS> --model i219v [--lan-switch] --filename <BLOB FILE NAME>`

## Datasheets

[82579LM / 82579V](https://github.com/Thrilleratplay/gbe_generator_datasheets/blob/main/Intel%2082579%20Gigabit%20Ethernet%20PHY82579-datasheetvol21.pdf)
[i217LM / i217V](https://github.com/Thrilleratplay/gbe_generator_datasheets/blob/main/i217-ethernet-controller-datasheet-2.pdf)
[i218LM / i218V](https://github.com/Thrilleratplay/gbe_generator_datasheets/blob/main/i218-ethernet-connection-datasheet-275854.pdf)
[i219LM / i219V](https://github.com/Thrilleratplay/gbe_generator_datasheets/blob/main/ethernet-connection-i219-datasheet-2.pdf)
