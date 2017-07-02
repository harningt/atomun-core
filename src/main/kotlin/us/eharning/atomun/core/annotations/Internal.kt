/*
 * Copyright 2017 Thomas Harning Jr. <harningt@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package us.eharning.atomun.core.annotations

/**
 * Signifies that a private API (public class, method or field) is internal and should not be used.
 * An API bearing this annotation is exempt from any compatibility guarantees made by its containing library.
 * Note that the presence of this annotation implies nothing about the quality or performance of the API in
 * question, only the fact that it is not to be used by outside projects.
 *
 * Such an API may be marked as such since it may not be able to be moved to an appropriate
 * "internal" package due to package visibility requirements.
 */
@kotlin.annotation.Retention(AnnotationRetention.BINARY)
@kotlin.annotation.Target(
        AnnotationTarget.ANNOTATION_CLASS,
        AnnotationTarget.CONSTRUCTOR,
        AnnotationTarget.FIELD,
        AnnotationTarget.FUNCTION,
        AnnotationTarget.PROPERTY_GETTER,
        AnnotationTarget.PROPERTY_SETTER,
        AnnotationTarget.CLASS,
        AnnotationTarget.FILE
)
@MustBeDocumented
annotation class Internal
