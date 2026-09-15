"""base plugin providing helper functions for dealing with lief data."""

from typing import Any

from azul_runner import BinaryPlugin, FeatureValue


class AzulPluginLiefBase(BinaryPlugin):
    """A base class providing helpful functions."""

    SAMPLE_SIZE = 50
    CLIPPING_SIZE = 30

    def feature_label_validator(self, label: bytes | str | None) -> str | None:
        """Takes potential labels and ensures they are usable.

        - only contain valid unicode: otherwise we'll get a validation error
        - do not exceeded SAMPLE_SIZE: labels should just provide context not actual data
        """
        match label:
            case bytes():
                data = label.decode(errors="backslashreplace")[: self.SAMPLE_SIZE]
            case str():
                # strings that do not originate in python could have smuggled in invalid utf-8.
                # Take it to bytes, then decode it back to ensure we eliminate them
                data = label.encode().decode(errors="backslashreplace")[: self.SAMPLE_SIZE]
            case None:
                data = None
            case _:
                self.logger.error(f"Unknown label type {type(label)}")
                data = ""
        return data

    def feature_value_validator(self, feature_key: str, feature_value: str | bytes):
        """Checks a feature value for "correctness".

        Auto marks self as malformed if feature value breaks a rule.
        """
        if len(feature_value) > self.cfg.max_value_length:
            self.is_malformed(
                f"Feature value too long ({feature_key}) [ACTUAL SIZE: {len(feature_value)}]: {feature_value[: self.SAMPLE_SIZE]}"
            )
            feature_value = feature_value[: self.CLIPPING_SIZE]

        return feature_value

    def feature_validator(self, features: dict[str, Any]) -> None:
        """Take a feature dict and ensure it's features are sane.

        Use before adding all features to job to get a logged list of malformed.
        Makes self.malformed_features dict available

        - ensure no feature value length surpasses max_value_length
        - validate all labels using feature_label_validator

        Modifies dictionary and lists in place.

        Runtime: O(n+m) where n is the number of keys and m is the number of values
        Memory: O(2n)
        """
        self.malformed_features: dict[str, list[str] | str] = dict()

        for feat in features.items():
            match feat[1]:
                case str():
                    if len(feat[1]) > self.cfg.max_value_length:
                        self.malformed_features[feat[0]] = "Value too long"
                        features[feat[0]] = feat[1][: self.CLIPPING_SIZE]
                case FeatureValue():
                    value = feat[1]
                    remake = False
                    new_value = value.value
                    new_label = value.label

                    if isinstance(value.value, str) or isinstance(value.value, bytes):
                        if len(value.value) > self.cfg.max_value_length:
                            self.malformed_features[feat[0]] = (
                                f"Value too long ({len(value.value)}): {value.value[: self.SAMPLE_SIZE]}"
                            )
                            new_value = value.value[: self.CLIPPING_SIZE]
                            remake = True

                    if value.label and len(value.label) > self.SAMPLE_SIZE:
                        new_label = self.feature_label_validator(value.label)
                        remake = True

                    if remake:
                        features[feat[0]] = FeatureValue(
                            new_value,
                            label=new_label,
                            offset=value.offset,
                            size=value.size,
                        )
                case list():
                    self._feature_list_validator(features, feat[0])

        if len(self.malformed_features) > 0:
            self.logger.error(f"MALFORMED FEATURES: {self.malformed_features}")

    def _feature_list_validator(self, features: dict[str, list[str | bytes | FeatureValue]], feature_key: str) -> None:
        """Check val and label."""
        self.malformed_features[feature_key] = []

        feature_list = features[feature_key]

        if len(feature_list) > self.cfg.max_values_per_feature:
            self.malformed_features[feature_key].append("Too many values")  # type: ignore Will alway be a list
            features[feature_key] = feature_list[: self.cfg.max_values_per_feature]
            feature_list = features[feature_key]

        target_list: list[str | bytes | FeatureValue] = feature_list
        malformed_list: list[str] = self.malformed_features[feature_key]  # type: ignore
        for i in range(len(target_list)):
            match target_list[i]:
                case str():
                    value_str: str = target_list[i]  # type: ignore
                    if len(value_str) > self.cfg.max_value_length:
                        malformed_list.append(f"Value too long ({len(value_str)}): {value_str[: self.SAMPLE_SIZE]}")
                        target_list[i] = value_str[: self.CLIPPING_SIZE]
                case bytes():
                    value_bytes: bytes = target_list[i]  # type: ignore
                    if len(value_bytes) > self.cfg.max_value_length:
                        malformed_list.append(
                            f"Value too long ({len(value_bytes)}): {value_bytes[: self.SAMPLE_SIZE]}"
                        )
                        target_list[i] = value_bytes[: self.CLIPPING_SIZE]
                case FeatureValue():
                    value: FeatureValue = target_list[i]  # type: ignore
                    remake = False
                    new_value = value.value
                    new_label = value.label

                    if isinstance(value.value, str) or isinstance(value.value, bytes):
                        if len(value.value) > self.cfg.max_value_length:
                            malformed_list.append(
                                f"Value too long ({len(value.value)}): {value.value[: self.SAMPLE_SIZE]}"
                            )
                            new_value = value.value[: self.CLIPPING_SIZE]
                            remake = True

                    if value.label and len(value.label) > self.SAMPLE_SIZE:
                        new_label = self.feature_label_validator(value.label)
                        remake = True

                    if remake:
                        target_list[i] = FeatureValue(
                            new_value,
                            label=new_label,
                            offset=value.offset,
                            size=value.size,
                        )
        if len(self.malformed_features[feature_key]) < 1:
            self.malformed_features.pop(feature_key)
